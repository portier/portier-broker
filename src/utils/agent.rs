//! Simple implementation of the agent pattern.
//!
//! This allows us to better model the processes in Portier that run on a separate track from the
//! HTTP server. Specifically, this is built to reuse the Tokio threads, while also making it easy
//! to create abstractions that can be implemented with either synchronous or asynchronous code.
//!
//! The way this is used is to have a type implement `Agent`, then construct it and call
//! `spawn_agent` with it, which will return an `Addr`. The `Addr` can be cheaply cloned and used
//! to send messages to the agent. It's also possible to abstract over a message type by casting it
//! to a `dyn Sender<M>`.
//!
//! Messages are defined as types that implement the `Message` trait. Agents process these in
//! implementations of the `Handler<M>` trait.

use std::any::type_name;
use std::future::Future;
use std::pin::Pin;
use std::task::{self, Poll};
use tokio::sync::{mpsc, oneshot};

/// A trait for messages that can be sent to an agent.
pub trait Message: Send + 'static {
    /// The type of reply sent back by the agent.
    type Reply: Send + 'static;
}

/// A message used for the `Agent::started` context.
pub struct AgentStarted;
impl Message for AgentStarted {
    type Reply = ();
}

/// Context passed to handlers, used to send a reply.
///
/// The agent must call one of the reply methods, which consumes the context. The context may not
/// otherwise be dropped.
pub struct Context<A, M: Message> {
    tx: oneshot::Sender<M::Reply>,
    addr: Addr<A>,
}

impl<A, M: Message> Context<A, M> {
    /// Build a new context.
    fn new(addr: &Addr<A>) -> (Self, ReplyFuture<M>) {
        let (tx, rx) = oneshot::channel();
        let addr = addr.clone();
        let cx = Self { tx, addr };
        let reply_fut = ReplyFuture { rx };
        (cx, reply_fut)
    }

    /// Send a reply to the message.
    pub fn reply(self, reply: M::Reply) {
        let _res = self.tx.send(reply);
    }

    /// Execute the function and send the return value as the reply.
    ///
    /// This is useful for blocks of code that operate on `Result`, and would benefit from using
    /// the `?`-operator.
    #[allow(dead_code)]
    pub fn reply_with<F>(self, f: F)
    where
        F: FnOnce() -> M::Reply,
    {
        let _res = self.tx.send(f());
    }

    /// Spawn an async task that returns a reply later.
    pub fn reply_later<F>(self, f: F)
    where
        F: Future<Output = M::Reply> + Send + 'static,
    {
        let Context { tx, .. } = self;
        tokio::spawn(async move {
            let _res = tx.send(f.await);
        });
    }

    /// Get the address of the agent itself.
    pub fn addr(&self) -> &Addr<A> {
        &self.addr
    }
}

/// Future for a reply from an agent.
pub struct ReplyFuture<M: Message> {
    rx: oneshot::Receiver<M::Reply>,
}

impl<M: Message> Future for ReplyFuture<M> {
    type Output = M::Reply;

    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context) -> Poll<Self::Output> {
        Pin::new(&mut self.rx)
            .poll(cx)
            .map(|val| val.expect("agent did not send a reply"))
    }
}

/// Closure via which messages are received by the agent message loop.
///
/// These closures can simply be called to invoke the correct message handler, whenever the message
/// loop is ready to do so.
pub type DispatchFn<A> = Box<dyn FnOnce(&mut A) + Send + 'static>;

/// A trait for types that represent agents.
///
/// Types implementing this encapsulate agent state and behavior.
pub trait Agent: Send + Sized + 'static {
    /// Spawn the message loop.
    ///
    /// The default implementation spawns a Tokio task that processes messages from the receiver in
    /// an infinite loop. Each message is wrapped in a `block_in_place` to allow handlers to do
    /// synchronous work while holding a mutable reference to the agent.
    fn spawn_loop(mut self, mut rx: mpsc::Receiver<DispatchFn<Self>>) {
        tokio::spawn(async move {
            while let Some(dispatch) = rx.recv().await {
                tokio::task::block_in_place(|| {
                    dispatch(&mut self);
                });
            }
        });
    }

    /// Called once the agent is started.
    ///
    /// Agents can implement this to start async tasks, such as doing maintenance periodically. The
    /// implementation works like a regular message handler. It can block and has mutable access to
    /// the agent itself.
    fn started(&mut self, cx: Context<Self, AgentStarted>) {
        cx.reply(());
    }
}

/// Start the agent.
///
/// This function starts the agent message loop, and waits for the `started` method to complete.
/// The return value is the agent address.
pub async fn spawn_agent<A: Agent>(agent: A) -> Addr<A> {
    log::trace!("Starting agent {:?}", type_name::<A>());
    let (addr, rx) = Addr::new();
    let (cx, reply_fut) = Context::new(&addr);
    let tx = addr.tx.clone();
    tokio::spawn(async move {
        let send_fut = tx.send(Box::new(move |agent: &mut A| {
            agent.started(cx);
        }));
        if send_fut.await.is_err() {
            panic!("agent stopped before startup completed");
        }
    });
    agent.spawn_loop(rx);
    reply_fut.await;
    log::trace!("Started agent {:?}", type_name::<A>());
    addr
}

/// Trait implemented by agents for each message type they handle.
pub trait Handler<M: Message>: Sized {
    /// Handle the message.
    ///
    /// Handlers are called one-by-one as messages arrive; the next message won't be picked up
    /// until the function returns. Handlers can block and have mutable access to the agent itself.
    ///
    /// A context is provided to send the reply, and it can live longer than the function, which
    /// allows agents to spawn an async task while continuing with the next message.
    fn handle(&mut self, message: M, cx: Context<Self, M>);
}

/// An address to an agent.
///
/// Can be cheaply cloned, and is used to send messages to the agent. It's also possible to
/// abstract over a message type by casting it to a `dyn Sender<M>`.
pub struct Addr<A> {
    tx: mpsc::Sender<DispatchFn<A>>,
}

impl<A> Addr<A> {
    /// Create a new address for an agent type.
    fn new() -> (Addr<A>, mpsc::Receiver<DispatchFn<A>>) {
        let (tx, rx) = mpsc::channel(8);
        let addr = Addr { tx };
        (addr, rx)
    }

    /// Sends a message to the agent.
    pub fn send<M>(&self, message: M) -> ReplyFuture<M>
    where
        M: Message,
        A: Handler<M> + Send + 'static,
    {
        log::trace!(
            "Sending message {:?} to agent {:?}",
            type_name::<M>(),
            type_name::<A>()
        );
        let (cx, reply_fut) = Context::new(self);
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let send_fut = tx.send(Box::new(move |agent: &mut A| {
                agent.handle(message, cx);
            }));
            if send_fut.await.is_err() {
                panic!("tried to send message to stopped agent");
            }
        });
        reply_fut
    }
}

impl<A> Clone for Addr<A> {
    fn clone(&self) -> Self {
        let tx = self.tx.clone();
        Addr { tx }
    }
}

/// Trait implemented by `Addr` that allows trait objects to be created per message.
pub trait Sender<M: Message>: Send + Sync {
    /// Sends a message of this type to the agent.
    fn send(&self, message: M) -> ReplyFuture<M>;
}

impl<M, A> Sender<M> for Addr<A>
where
    M: Message,
    A: Handler<M> + Send + 'static,
{
    fn send(&self, message: M) -> ReplyFuture<M> {
        Addr::<A>::send(self, message)
    }
}
