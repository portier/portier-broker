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
use std::task::{Context, Poll};
use tokio::sync::oneshot;

/// A trait for messages that can be sent to an agent.
pub trait Message: Send + 'static {
    /// The type of reply sent back by the agent.
    type Reply: Send + 'static;
}

/// Channel type used by agents to send replies.
///
/// The agent must call one of `send` or `later` to consume the sender, and may not otherwise drop
/// the sender without sending a reply.
pub struct ReplySender<M: Message> {
    tx: oneshot::Sender<M::Reply>,
}

impl<M: Message> ReplySender<M> {
    /// Send a reply to the message.
    pub fn send(self, reply: M::Reply) {
        let _ = self.tx.send(reply);
    }

    /// Spawn an async task that returns a reply later.
    pub fn later<F>(self, f: F)
    where
        F: Future<Output = M::Reply> + Send + 'static,
    {
        tokio::spawn(async move { self.send(f.await) });
    }
}

/// Channel type used to receive replies from an agent.
///
/// This can simply be used as a `Future`.
pub struct ReplyReceiver<T> {
    rx: oneshot::Receiver<T>,
}

impl<T> Future for ReplyReceiver<T> {
    type Output = T;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
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
pub trait Handler<M: Message> {
    /// Handle the message.
    ///
    /// Handlers are called one-by-one as messages arrive; the next message won't be picked up
    /// until the function returns. Handlers have mutable access to the agent itself.
    ///
    /// A reply channel is provided to send the reply, and it can live longer than the function,
    /// which allows agents to spawn an async task while continuing with the next message.
    fn handle(&mut self, message: M, reply: ReplySender<M>);
}

/// An address to an agent.
///
/// Can be cheaply cloned, and is used to send messages to the agent. It's also possible to
/// abstract over a message type by casting it to a `dyn Sender<M>`.
pub struct Addr<T> {
    agent: Arc<Mutex<T>>,
}

impl<T> Addr<T> {
    /// Sends a message to the agent.
    pub fn send<M>(&self, message: M) -> ReplyReceiver<M::Reply>
    where
        M: Message,
        T: Handler<M> + Send + 'static,
    {
        let (tx, rx) = oneshot::channel();
        let agent = self.agent.clone();
        tokio::task::spawn_blocking(move || {
            let mut agent = agent.lock().unwrap();
            agent.handle(message, ReplySender { tx });
        });
        ReplyReceiver { rx }
    }
}

impl<T> Clone for Addr<T> {
    fn clone(&self) -> Self {
        let agent = self.agent.clone();
        Addr { agent }
    }
}

/// Trait implemented by `Addr` that allows trait objects to be created per message.
pub trait Sender<M: Message>: Send + Sync {
    /// Sends a message of this type to the agent.
    fn send(&self, message: M) -> ReplyReceiver<M::Reply>;
}

impl<M, T> Sender<M> for Addr<T>
where
    M: Message,
    T: Handler<M> + Send + 'static,
{
    fn send(&self, message: M) -> ReplyReceiver<M::Reply> {
        Addr::<T>::send(self, message)
    }
}
