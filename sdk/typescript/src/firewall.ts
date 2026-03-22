/**
 * Firewall class — async/await interface for the four v1 hook call sites.
 *   onPrompt(text: string): Promise<Decision>
 *   onContext(chunks: string[]): Promise<ChunkResult[]>
 *   onToolCall(name: string, params: Record<string, unknown>): Promise<Decision>
 *   onMemory(key: string, value: string, op: string): Promise<Decision>
 */
