use futures_util::future::poll_fn;
use redis::{ConnectionAddr, ConnectionInfo, ErrorKind, RedisError, RedisResult, Value};
use std::collections::hash_map::{Entry, HashMap};
use std::future::Future;
use std::io::Result as IoResult;
use std::net::ToSocketAddrs;
use std::pin::Pin;
use std::task::Poll;
use tokio::io::{self, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::stream::Stream;
use tokio::sync::{broadcast, mpsc, oneshot};

#[cfg(unix)]
use tokio::net::UnixStream;

/// Read half of a Redis pubsub connection.
struct ReadHalf(io::BufReader<Box<dyn io::AsyncRead + Unpin + Send>>);
impl ReadHalf {
    /// Read a value from Redis.
    async fn read(&mut self) -> RedisResult<Value> {
        redis::parse_redis_value_async(&mut self.0).await
    }
}

/// Write half of a Redis pubsub connection.
struct WriteHalf(Box<dyn io::AsyncWrite + Unpin + Send>);
impl WriteHalf {
    /// Write a command on the Redis connection.
    async fn write(&mut self, cmd: &[&[u8]]) -> IoResult<()> {
        let mut data = format!("*{}\r\n", cmd.len()).into_bytes();
        for part in cmd {
            data.append(&mut format!("${}\r\n", part.len()).into_bytes());
            data.extend_from_slice(part);
            data.extend_from_slice(b"\r\n");
        }
        self.0.write_all(&data).await
    }
}

/// Channel type used to receive pubsub messages.
pub type RecvChan = broadcast::Receiver<Vec<u8>>;

/// Channel type used to reply to `Cmd`.
type ReplyChan = oneshot::Sender<RecvChan>;

/// Command type sent to the connection loop.
struct Cmd {
    /// Channel to subscribe to.
    chan: Vec<u8>,
    /// Reply channel for the command.
    reply: ReplyChan,
}

/// Tracks an active subscription on the Redis server.
struct Sub {
    /// Channel sender used to notify all logical subscribers.
    tx: broadcast::Sender<Vec<u8>>,
    /// Reply channels that are awaiting confirmation.
    pending: Option<Vec<ReplyChan>>,
}

/// Polling events that can happen in the connection loop.
enum LoopEvent {
    Cmd(Cmd),
    CmdClosed,
    Interval,
    Read((RedisResult<Value>, ReadHalf)),
}

/// The Redis pubsub connection loop.
async fn conn_loop(mut rx: ReadHalf, mut tx: WriteHalf, mut cmd: mpsc::Receiver<Cmd>) {
    let interval = tokio::time::interval(tokio::time::Duration::from_secs(20));
    tokio::pin!(interval);

    // TODO: The redis crate has a ValueCodec, but doesn't expose it. This is a workaround.
    let mut read_fut: Pin<Box<dyn Future<Output = _> + Send>> = Box::pin(async move {
        let res = rx.read().await;
        (res, rx)
    });

    let mut subs: HashMap<Vec<u8>, Sub> = HashMap::new();

    loop {
        // This specifically prioritizes processing commands over receiving.
        match poll_fn(|cx| {
            if let Poll::Ready(res) = cmd.poll_recv(cx) {
                match res {
                    Some(cmd) => Poll::Ready(LoopEvent::Cmd(cmd)),
                    None => Poll::Ready(LoopEvent::CmdClosed),
                }
            } else if let Poll::Ready(_) = interval.as_mut().poll_next(cx) {
                Poll::Ready(LoopEvent::Interval)
            } else if let Poll::Ready(res) = read_fut.as_mut().poll(cx) {
                Poll::Ready(LoopEvent::Read(res))
            } else {
                Poll::Pending
            }
        })
        .await
        {
            LoopEvent::Cmd(Cmd { chan, reply }) => match subs.entry(chan.clone()) {
                // If already subscribed, reply with a broadcast channel immediately. Otherwise,
                // add the reply channel to `pending`, and send the Redis subscribe command if
                // necessary.
                Entry::Occupied(mut entry) => {
                    let sub = entry.get_mut();
                    if let Some(ref mut pending) = sub.pending {
                        pending.push(reply);
                    } else {
                        let _ = reply.send(sub.tx.subscribe());
                    }
                }
                Entry::Vacant(entry) => {
                    entry.insert(Sub {
                        tx: broadcast::channel(8).0,
                        pending: Some(vec![reply]),
                    });
                    tx.write(&[b"SUBSCRIBE", &chan])
                        .await
                        .expect("Failed to send subscribe command to Redis");
                }
            },
            LoopEvent::CmdClosed => {
                // TODO: Stop reading from the command channel.
                // This, plus an empty `subs`, means we can exit.
                unimplemented!();
            }
            LoopEvent::Interval => {
                // Unsubscribe from channels that no longer have subscribers, or send a ping.
                let to_unsub: Vec<Vec<u8>> = subs
                    .iter()
                    .filter_map(|(chan, sub)| {
                        if sub.tx.receiver_count() == 0 {
                            Some(chan.clone())
                        } else {
                            None
                        }
                    })
                    .collect();
                if to_unsub.is_empty() {
                    tx.write(&[b"PING"])
                        .await
                        .expect("Failed to send ping command to Redis");
                } else {
                    for chan in &to_unsub {
                        subs.remove(chan);
                    }
                    let mut unsub_cmd: Vec<&[u8]> = vec![b"UNSUBSCRIBE"];
                    unsub_cmd.extend(to_unsub.iter().map(|chan| &chan[..]));
                    tx.write(&unsub_cmd)
                        .await
                        .expect("Failed to send unsubscribe command to Redis");
                }
            }
            LoopEvent::Read((res, mut rx)) => {
                read_fut = Box::pin(async move {
                    let res = rx.read().await;
                    (res, rx)
                });
                let value = res.expect("Failed to read from Redis");
                let vec = match value {
                    // Note: If we have no subscriptions at all, we receive pongs as regular
                    // replies instead of events.
                    Value::Status(status) if status == "PONG" => continue,
                    Value::Bulk(ref vec) if vec.len() >= 2 => vec,
                    _ => panic!("Unexpected value from Redis: {:?}", value),
                };
                match (&vec[0], &vec[1], vec.get(2)) {
                    // Handle a message event by sending on the broadcast channel.
                    (
                        &Value::Data(ref ev),
                        &Value::Data(ref chan),
                        Some(&Value::Data(ref data)),
                    ) if ev == b"message" => {
                        if let Some(ref sub) = subs.get(&chan[..]) {
                            let _ = sub.tx.send(data.to_vec());
                        }
                    }
                    // Handle subscription confirmation by sending out pending replies.
                    (&Value::Data(ref ev), &Value::Data(ref chan), _) if ev == b"subscribe" => {
                        if let Some(ref mut sub) = subs.get_mut(&chan[..]) {
                            if let Some(pending) = sub.pending.take() {
                                for reply in pending {
                                    let _ = reply.send(sub.tx.subscribe());
                                }
                            }
                        }
                    }
                    // Some other events are ok, but we do nothing with them.
                    (&Value::Data(ref ev), _, _) if ev == b"unsubscribe" || ev == b"pong" => {}
                    _ => panic!("Unexpected value from Redis: {:?}", value),
                }
            }
        }
    }
}

/// A Subscriber can be used to subscribe to Redis pubsub channels.
///
/// This struct can be cheaply cloned. It is simply a client of the connection loop which is
/// running in another task.
#[derive(Clone)]
pub struct Subscriber {
    cmd: mpsc::Sender<Cmd>,
}

impl Subscriber {
    /// Subscribe to a channel.
    ///
    /// This function does not complete until the server has confirmed the subscription.
    pub async fn subscribe(&mut self, chan: Vec<u8>) -> broadcast::Receiver<Vec<u8>> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let cmd = Cmd {
            chan,
            reply: reply_tx,
        };
        if self.cmd.send(cmd).await.is_ok() {
            if let Ok(rx) = reply_rx.await {
                return rx;
            }
        }
        panic!("Tried to subscribe on closed pubsub connection");
    }
}

/// Make a pubsub connection to Redis.
pub async fn connect(info: &ConnectionInfo) -> RedisResult<Subscriber> {
    // Note: This code is borrowed from the redis crate.
    let (rx, tx): (
        Box<dyn io::AsyncRead + Unpin + Send>,
        Box<dyn io::AsyncWrite + Unpin + Send>,
    ) = match *info.addr {
        ConnectionAddr::Tcp(ref host, port) => {
            let socket_addr = {
                let mut socket_addrs = (&host[..], port).to_socket_addrs()?;
                match socket_addrs.next() {
                    Some(socket_addr) => socket_addr,
                    None => {
                        return Err(RedisError::from((
                            ErrorKind::InvalidClientConfig,
                            "No address found for host",
                        )));
                    }
                }
            };

            let (rx, tx) = io::split(TcpStream::connect(&socket_addr).await?);
            (Box::new(rx), Box::new(tx))
        }

        #[cfg(unix)]
        ConnectionAddr::Unix(ref path) => {
            let (rx, tx) = io::split(UnixStream::connect(path).await?);
            (Box::new(rx), Box::new(tx))
        }

        #[cfg(not(unix))]
        ConnectionAddr::Unix(_) => {
            return Err(RedisError::from((
                ErrorKind::InvalidClientConfig,
                "Cannot connect to unix sockets \
                 on this platform",
            )))
        }
    };

    let mut rx = ReadHalf(io::BufReader::new(rx));
    let mut tx = WriteHalf(tx);

    if let Some(ref passwd) = info.passwd {
        tx.write(&[b"AUTH", passwd.as_bytes()]).await?;
        match rx.read().await {
            Ok(Value::Okay) => (),
            _ => {
                return Err((
                    ErrorKind::AuthenticationFailed,
                    "Password authentication failed",
                )
                    .into());
            }
        }
    }

    // Note: Pubsub ignores database ID, so we don't need to send `SELECT`.

    let (cmd_tx, cmd_rx) = mpsc::channel(8);
    tokio::spawn(conn_loop(rx, tx, cmd_rx));
    Ok(Subscriber { cmd: cmd_tx })
}
