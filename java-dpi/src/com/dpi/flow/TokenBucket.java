package com.dpi.flow;

/**
 * A lightweight, lock-free token bucket algorithm for rate limiting.
 * Since this is bound to a single Flow and executed by a single Worker thread
 * due to flow affinity, we do not need synchronization primitives like
 * AtomicLong.
 */
public class TokenBucket {

    private final long capacityBytes;
    private final long refillRateBytesPerSec;

    private long currentTokens;
    private long lastRefillTimeNanos;

    public TokenBucket(long bytesPerSecond, long initialTimestampNanos) {
        // We set capacity to exactly 1 second worth of bytes to allow a burst
        // up to the per-second rate limit.
        this.capacityBytes = bytesPerSecond;
        this.refillRateBytesPerSec = bytesPerSecond;
        this.currentTokens = capacityBytes;
        this.lastRefillTimeNanos = initialTimestampNanos;
    }

    /**
     * Checks if the packet of the given size is allowed to pass.
     * If allowed, deducts the tokens and returns true.
     * If not allowed, returns false (packet should be dropped/delayed).
     * 
     * @param requestedBytes        The size of the packet
     * @param currentTimestampNanos The current time
     * @return true if allowed, false if rate limit exceeded
     */
    public boolean tryConsume(long requestedBytes, long currentTimestampNanos) {
        // If there's no limit (e.g. rate <= 0), always allow
        if (capacityBytes <= 0) {
            return true;
        }

        refill(currentTimestampNanos);

        if (currentTokens >= requestedBytes) {
            currentTokens -= requestedBytes;
            return true;
        }

        return false;
    }

    private void refill(long currentTimestampNanos) {
        long nanosElapsed = currentTimestampNanos - lastRefillTimeNanos;

        // Only trigger refill if enough time has passed to accumulate at least 1 byte
        // to avoid expensive and repetitive math for extremely rapid packets.
        if (nanosElapsed > 0) {
            // (nanosElapsed / 1_000_000_000.0) * refillRateBytesPerSec
            // We use integer math to avoid double precision issues and maintain speed.
            // Be careful to avoid overflow: nanosElapsed * refillRate could overflow if
            // both are large.
            // Alternatively:
            long tokensToAdd = (nanosElapsed * refillRateBytesPerSec) / 1_000_000_000L;

            if (tokensToAdd > 0) {
                currentTokens = Math.min(capacityBytes, currentTokens + tokensToAdd);

                // Advance the time, but leave remainder to prevent drift over time.
                long nanosConsumed = (tokensToAdd * 1_000_000_000L) / refillRateBytesPerSec;
                lastRefillTimeNanos += nanosConsumed;
            }
        }
    }
}
