//! Device selection: CUDA > Metal > CPU fallback.

use candle_core::Device;

/// Select the best available compute device.
///
/// Tries CUDA first (when compiled with `cuda` feature), then Metal
/// (when compiled with `metal` feature), then falls back to CPU.
pub fn select_device() -> Device {
    #[cfg(feature = "cuda")]
    {
        if let Ok(device) = Device::new_cuda(0) {
            tracing::info!("Using CUDA device 0");
            return device;
        }
        tracing::warn!("CUDA feature enabled but no GPU available, falling back");
    }

    #[cfg(feature = "metal")]
    {
        if let Ok(device) = Device::new_metal(0) {
            tracing::info!("Using Metal device 0");
            return device;
        }
        tracing::warn!("Metal feature enabled but no device available, falling back");
    }

    Device::Cpu
}
