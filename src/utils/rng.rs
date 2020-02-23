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
