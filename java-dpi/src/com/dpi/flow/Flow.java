package com.dpi.flow;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Represents a network flow (a connection between two endpoints).
 * Tracks bytes, packets, and application-level details like HTTP Host or TLS
 * SNI.
 */
public class Flow {
    private final FiveTuple fiveTuple;
    private final long startTime;
    private long lastSeenTime;

    // We use AtomicLong so multiple threads can update stats lock-free
    private final AtomicLong bytesTransferred = new AtomicLong(0);
    private final AtomicLong packetsTransferred = new AtomicLong(0);

    // optional rate limiter - only set if a rate limit is configured for this flow
    private TokenBucket rateLimiter;

    private boolean blocked = false;
    private String blockReason;

    private boolean closed = false;

    // Protocol details
    private boolean fullyParsed = false;
    private String applicationProtocol; // like "HTTP" or "TLS"
    private String sniOrHost; // the extracted domain name

    public Flow(FiveTuple fiveTuple, long startTime) {
        this.fiveTuple = fiveTuple;
        this.startTime = startTime;
        this.lastSeenTime = startTime;
    }

    /**
     * Called every time a new packet arrives for this flow.
     */
    public void addBytes(int bytes) {
        this.bytesTransferred.addAndGet(bytes);
        this.packetsTransferred.incrementAndGet();
        this.lastSeenTime = System.currentTimeMillis();
    }

    public FiveTuple getFiveTuple() {
        return fiveTuple;
    }

    public synchronized long getLastSeenTime() {
        return lastSeenTime;
    }

    public synchronized boolean isBlocked() {
        return blocked;
    }

    public synchronized void setBlocked(boolean blocked, String reason) {
        this.blocked = blocked;
        this.blockReason = reason;
    }

    public synchronized String getBlockReason() {
        return blockReason;
    }

    public synchronized boolean isClosed() {
        return closed;
    }

    public synchronized void setClosed(boolean closed) {
        this.closed = closed;
    }

    public synchronized boolean isFullyParsed() {
        return fullyParsed;
    }

    public synchronized void setFullyParsed(boolean fullyParsed) {
        this.fullyParsed = fullyParsed;
    }

    public synchronized Optional<String> getApplicationProtocol() {
        return Optional.ofNullable(applicationProtocol);
    }

    public synchronized void setApplicationProtocol(String protocol) {
        this.applicationProtocol = protocol;
    }

    public synchronized Optional<String> getSniOrHost() {
        return Optional.ofNullable(sniOrHost);
    }

    public synchronized void setSniOrHost(String sniOrHost) {
        this.sniOrHost = sniOrHost;
    }

    public long getBytesTransferred() {
        return bytesTransferred.get();
    }

    public long getPacketsTransferred() {
        return packetsTransferred.get();
    }

    // set a rate limiter on this flow (called when flow is first created with a
    // limit)
    public void setRateLimiter(TokenBucket bucket) {
        this.rateLimiter = bucket;
    }

    // returns true if the packet is allowed through, false if rate limit exceeded
    // if no limiter is set just always allow it
    public boolean tryConsumeBandwidth(int bytes, long timestampNanos) {
        if (rateLimiter == null)
            return true;
        return rateLimiter.tryConsume(bytes, timestampNanos);
    }
}
