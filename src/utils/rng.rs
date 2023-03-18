use ring::rand::{SecureRandom as GeneratorTrait, SystemRandom};
use tokio::task::spawn_blocking;

#[derive(Clone)]
pub struct SecureRandom {
    pub generator: SystemRandom,
}

impl SecureRandom {
    pub async fn new() -> Self {
        let generator = SystemRandom::new();
        let res = Self { generator };
        // Per SystemRandom docs, call `fill` once here to prepare the generator.
        res.generate_async(16).await;
        res
    }

    pub fn generate(&self, bytes: usize) -> Vec<u8> {
        let mut res = vec![0; bytes];
        self.generator
            .fill(&mut res[..])
            .expect("secure random number generator failed");
        res
    }

    pub async fn generate_async(&self, bytes: usize) -> Vec<u8> {
        let clone = self.clone();
        spawn_blocking(move || clone.generate(bytes))
            .await
            .expect("secure random number generator panicked")
    }
}

#[cfg(feature = "rand_core")]
impl rand_core::RngCore for SecureRandom {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest)
            .expect("secure random number generator failed");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.generator
            .fill(dest)
            .map_err(|_| rand_core::Error::new("secure random number generator failed"))
    }
}

#[cfg(feature = "rand_core")]
impl rand_core::CryptoRng for SecureRandom {}
