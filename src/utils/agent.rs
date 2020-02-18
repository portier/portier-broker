//! Simple implementation of the agent pattern.
//!
//! This is really a poor man's implementation that doesn't even use a real message queue, but
//! simply uses a `Mutex` to emulate message processing. Still, this works will for our purposes,
//! and allows us to better model the various processes in Portier.
//!
//! The way this is used is to have a type implement `Agent`, then construct it and call
//! `Agent::start` on it, which will return an `Addr`. The `Addr` can be cheaply cloned and used to
//! send messages to the agent. It's also possible to abstract over a message type by casting it to
//! a `dyn Sender<M>`.
//!
//! Messages are defined as types that implement the `Message` trait. Agents process these in
//! implementations of the `Handler<M>` trait.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{self, Poll};
use tokio::sync::oneshot;

/// A trait for messages that can be sent to an agent.
pub trait Message: Send + 'static {
    /// The type of reply sent back by the agent.
    type Reply: Send + 'static;
}

/// Context passed to handlers, used to send a reply.
///
/// The agent must call one of `send` or `later` to consume the sender, and may not otherwise drop
/// the sender without sending a reply.
pub struct Context<A, M: Message> {
    tx: oneshot::Sender<M::Reply>,
    addr: Addr<A>,
}

impl<A, M: Message> Context<A, M> {
    /// Send a reply to the message.
    pub fn reply(self, reply: M::Reply) {
        let _ = self.tx.send(reply);
    }

    /// Execute the function and send the return value as the reply.
    ///
    /// This is useful for blocks of code that operate on Result, and would benefit from using the
    /// `?`-operator.
    pub fn reply_with<F>(self, f: F)
    where
        F: FnOnce() -> M::Reply,
    {
        let _ = self.tx.send(f());
    }

    /// Spawn an async task that returns a reply later.
    pub fn reply_later<F>(self, f: F)
    where
        F: Future<Output = M::Reply> + Send + 'static,
    {
        let Context { tx, .. } = self;
        tokio::spawn(async move {
            let _ = tx.send(f.await);
        });
    }

    /// Get the address of the agent itself.
    pub fn addr(&self) -> &Addr<A> {
        &self.addr
    }
}

/// Future for a reply from an agent.
pub struct ReplyFuture<T> {
    rx: oneshot::Receiver<T>,
}

impl<T> Future for ReplyFuture<T> {
    type Output = T;

    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context) -> Poll<Self::Output> {
        Pin::new(&mut self.rx)
            .poll(cx)
            .map(|val| val.expect("agent did not send a reply"))
    }
}

/// A trait for types that represent agents.
///
/// Types implementing this encapsulate agent state and behavior.
pub trait Agent: Sized {
    /// Start the agent. Returns the agent address.
    fn start(self) -> Addr<Self> {
        let agent = Arc::new(Mutex::new(self));
        let addr = Addr { agent };
        Self::started(&addr);
        addr
    }

    /// Called once the agent is started.
    ///
    /// Agents can implement this start async tasks, such as doing some maintenance at an interval.
    fn started(_addr: &Addr<Self>) {}
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
    agent: Arc<Mutex<A>>,
}

impl<A> Addr<A> {
    /// Sends a message to the agent.
    pub fn send<M>(&self, message: M) -> ReplyFuture<M::Reply>
    where
        M: Message,
        A: Handler<M> + Send + 'static,
    {
        log::debug!(
            "Sending {:?} to {:?}",
            std::any::type_name::<M>(),
            std::any::type_name::<A>()
        );
        let (tx, rx) = oneshot::channel();
        let addr = self.clone();
        tokio::task::spawn_blocking(move || {
            let mut agent = addr.agent.lock().expect("agent lock poisoned");
            agent.handle(
                message,
                Context {
                    tx,
                    addr: addr.clone(),
                },
            );
        });
        ReplyFuture { rx }
    }
}

impl<A> Clone for Addr<A> {
    fn clone(&self) -> Self {
        let agent = self.agent.clone();
        Addr { agent }
    }
}

/// Trait implemented by `Addr` that allows trait objects to be created per message.
pub trait Sender<M: Message>: Send + Sync {
    /// Sends a message of this type to the agent.
    fn send(&self, message: M) -> ReplyFuture<M::Reply>;
}

impl<M, A> Sender<M> for Addr<A>
where
    M: Message,
    A: Handler<M> + Send + 'static,
{
    fn send(&self, message: M) -> ReplyFuture<M::Reply> {
        Addr::<A>::send(self, message)
    }
}
