package io.ktor.utils.io

import kotlinx.coroutines.*
import kotlin.coroutines.*

/**
 * A coroutine job that is reading from a byte channel
 */
interface ReaderJob : Job {
    /**
     * A reference to the channel that this coroutine is reading from
     */
    val channel: ByteWriteChannel
}

/**
 * A coroutine job that is writing to a byte channel
 */
interface WriterJob : Job {
    /**
     * A reference to the channel that this coroutine is writing to
     */
    val channel: ByteReadChannel
}

interface ReaderScope : CoroutineScope {
    val channel: ByteReadChannel
}

interface WriterScope : CoroutineScope {
    val channel: ByteWriteChannel
}

fun CoroutineScope.reader(
    coroutineContext: CoroutineContext = EmptyCoroutineContext,
    channel: ByteChannel,
    block: suspend ReaderScope.() -> Unit
): ReaderJob = launchChannel(coroutineContext, channel, attachJob = false, block = block)

fun CoroutineScope.reader(
    coroutineContext: CoroutineContext = EmptyCoroutineContext,
    autoFlush: Boolean = false,
    block: suspend ReaderScope.() -> Unit
): ReaderJob = launchChannel(coroutineContext, ByteChannel(autoFlush), attachJob = true, block = block)

fun CoroutineScope.writer(
    coroutineContext: CoroutineContext = EmptyCoroutineContext,
    channel: ByteChannel,
    block: suspend WriterScope.() -> Unit
): WriterJob = launchChannel(coroutineContext, channel, attachJob = false, block = block)

fun CoroutineScope.writer(
    coroutineContext: CoroutineContext = EmptyCoroutineContext,
    autoFlush: Boolean = false,
    block: suspend WriterScope.() -> Unit
): WriterJob = launchChannel(coroutineContext, ByteChannel(autoFlush), attachJob = true, block = block)

/**
 * @param S not exactly safe (unchecked cast is used) so should be [ReaderScope] or [WriterScope]
 */
private fun <S : CoroutineScope> CoroutineScope.launchChannel(
    context: CoroutineContext,
    channel: ByteChannel,
    attachJob: Boolean,
    block: suspend S.() -> Unit
): ChannelJob {
    val originJob = coroutineContext[Job]
    val job = launch(context) {
        if (attachJob && originJob != null) {
            channel.attachJob(originJob)
        }

        @Suppress("UNCHECKED_CAST")
        val scope = ChannelScope(this, channel) as S

        try {
            block(scope)
        } catch (cause: Throwable) {
            if (originJob != null) {
                throw cause
            } else {
                channel.cancel(cause)
            }
        }
    }

    job.invokeOnCompletion { cause ->
        channel.close(cause)
    }

    return ChannelJob(job, channel)
}

private class ChannelScope(
    delegate: CoroutineScope,
    override val channel: ByteChannel
) : ReaderScope, WriterScope, CoroutineScope by delegate

private class ChannelJob(
    private val delegate: Job,
    override val channel: ByteChannel
) : ReaderJob, WriterJob, Job by delegate {
    override fun toString(): String = "ChannelJob[$delegate]"
}
