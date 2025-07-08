import { EventBus } from '../events/event-bus';
import { LLMClient } from '../types';
import { Logger } from '../utils/logger';
import { CybersecurityKnowledgeService } from './cybersecurity-knowledge-service';

export interface CacheEntry {
  response: string;
  timestamp: Date;
  accessCount: number;
  queryEmbedding: number[];
  contextHash: string;
  confidence: number;
  sources: string[];
  techniques: string[];
  tools: string[];
  codeExamples: string[];
  lastAccessed: Date;
  size: number; // Size in bytes for memory management
  ttl: number; // Time to live in milliseconds
}

export interface CAGQuery {
  query: string;
  context?: any;
  category?: string;
  difficulty?: string;
  maxResults?: number;
  includeCode?: boolean;
  includeTechniques?: boolean;
  useCache?: boolean;
  priority?: 'high' | 'normal' | 'low';
  timeout?: number; // Timeout in milliseconds
}

export interface CAGResult {
  response: string;
  cached: boolean;
  confidence: number;
  sources: string[];
  techniques: string[];
  tools: string[];
  codeExamples: string[];
  cacheHitType: 'exact' | 'similar' | 'none';
  similarityScore?: number;
  processingTime: number;
  cacheSize: number;
  memoryUsage: number;
}

export interface CAGPerformanceMetrics {
  totalQueries: number;
  cacheHits: number;
  cacheMisses: number;
  averageResponseTime: number;
  hitRate: number;
  memoryUsage: number;
  cacheSize: number;
  evictions: number;
  prewarmQueries: number;
}

export class CAGService {
  private readonly client: LLMClient;
  private readonly knowledgeService: CybersecurityKnowledgeService;
  private readonly eventBus: EventBus;
  private readonly logger: Logger;

  private readonly cache: Map<string, CacheEntry> = new Map();
  private readonly embeddingCache: Map<string, number[]> = new Map();
  private readonly performanceMetrics: CAGPerformanceMetrics = {
    totalQueries: 0,
    cacheHits: 0,
    cacheMisses: 0,
    averageResponseTime: 0,
    hitRate: 0,
    memoryUsage: 0,
    cacheSize: 0,
    evictions: 0,
    prewarmQueries: 0
  };

  // Production-optimized configuration
  private readonly maxCacheSize = 2000; // Increased for better hit rates
  private readonly maxMemoryUsage = 500 * 1024 * 1024; // 500MB max memory
  private readonly defaultCacheTTL = 7200 * 1000; // 2 hours default TTL
  private readonly similarityThreshold = 0.92; // Slightly lower for more hits
  private readonly embeddingCacheSize = 10000; // Increased embedding cache
  private readonly prewarmBatchSize = 50; // Batch size for pre-warming
  private readonly maxResponseTime = 10000; // 10 second timeout

  // Performance tracking
  private readonly responseTimes: number[] = [];
  private readonly maxResponseTimeHistory = 1000;

  constructor(
    client: LLMClient,
    knowledgeService: CybersecurityKnowledgeService,
    eventBus: EventBus
  ) {
    this.client = client;
    this.knowledgeService = knowledgeService;
    this.eventBus = eventBus;
    this.logger = new Logger('CAGService');

    if (typeof this.client.embed !== 'function') {
      const errorMsg = "CRITICAL: LLMClient does not have a functional 'embed' method. CAGService similarity features will be disabled or will fail.";
      this.logger.error(errorMsg);
      console.error(errorMsg); // Ensure visibility
      // Optionally, throw an error here to prevent service from starting in a broken state
      // throw new Error(errorMsg);
    }

    // Start periodic cache maintenance
    this.startCacheMaintenance();
  }

  /**
   * Main CAG query method with production optimizations
   */
  async query(query: CAGQuery): Promise<CAGResult> {
    const startTime = Date.now();
    const queryId = this.generateQueryId(query);

    this.performanceMetrics.totalQueries++;

    if (typeof this.client.embed !== 'function') {
      this.logger.error("CAGService.query: LLMClient 'embed' method is not available. Cannot perform similarity-based caching. Falling back to RAG or direct generation if possible.");
      // Fallback: attempt RAG without similarity caching, or error out
      const ragResult = await this.generateRAGResponse(query); // This itself might fail if it also tries to use embeddings indirectly
      return {
        ...ragResult,
        cached: false,
        cacheHitType: 'none',
        processingTime: Date.now() - startTime,
        cacheSize: this.cache.size,
        memoryUsage: this.getMemoryUsage(),
        confidence: ragResult.confidence || 0.1 // Low confidence as it's not from a tuned cache hit
      };
    }

    try {
      // Set timeout for the entire operation
      const timeout = query.timeout ?? this.maxResponseTime;
      const timeoutPromise = new Promise<never>((_, reject) => {
        setTimeout(() => reject(new Error('Query timeout')), timeout);
      });

      const queryPromise = this.executeQuery(query);
      const result = await Promise.race([queryPromise, timeoutPromise]);

      // Update performance metrics
      const responseTime = Date.now() - startTime;
      this.updatePerformanceMetrics(responseTime, result.cached);

      // Emit performance event
      this.eventBus.emit('cag.query.completed', {
        queryId,
        responseTime,
        cached: result.cached,
        cacheHitType: result.cacheHitType,
        confidence: result.confidence
      });

      return result;

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.logger.error(`CAG query failed: ${errorMessage}`, error);
      this.eventBus.emit('cag.query.failed', { queryId, error: errorMessage });

      return {
        response: `ERROR: ${errorMessage}`,
        cached: false,
        confidence: 0,
        sources: [],
        techniques: [],
        tools: [],
        codeExamples: [],
        cacheHitType: 'none',
        processingTime: Date.now() - startTime,
        cacheSize: this.cache.size,
        memoryUsage: this.getMemoryUsage(),
      };
    }
  }

  /**
   * Execute the actual query with caching
   */
  private async executeQuery(query: CAGQuery): Promise<CAGResult> {
    const startTime = Date.now();

    // Check for exact cache hit first
    const exactHit = await this.checkExactCacheHit(query);
    if (exactHit) {
      this.performanceMetrics.cacheHits++;
      this.logger.debug(`Exact cache hit for query: ${query.query.substring(0, 50)}...`);
      return {
        ...exactHit,
        cached: true,
        cacheHitType: 'exact',
        processingTime: Date.now() - startTime,
        cacheSize: this.cache.size,
        memoryUsage: this.getMemoryUsage()
      };
    }

    // Check for similar cache hit with lower threshold for high-priority queries
    const similarityThreshold = query.priority === 'high' ? 0.88 : this.similarityThreshold;
    const similarHit = await this.checkSimilarCacheHit(query, similarityThreshold);
    if (similarHit) {
      this.performanceMetrics.cacheHits++;
      this.logger.debug(`Similar cache hit for query: ${query.query.substring(0, 50)}...`);
      return {
        ...similarHit,
        cached: true,
        cacheHitType: 'similar',
        processingTime: Date.now() - startTime,
        cacheSize: this.cache.size,
        memoryUsage: this.getMemoryUsage()
      };
    }

    // Fall back to RAG generation
    this.performanceMetrics.cacheMisses++;
    const result = await this.generateRAGResponse(query);

    // Cache the new result with adaptive TTL
    await this.cacheResult(query, result);

    return {
      ...result,
      cached: false,
      cacheHitType: 'none',
      processingTime: Date.now() - startTime,
      cacheSize: this.cache.size,
      memoryUsage: this.getMemoryUsage()
    };
  }

  /**
   * Check for exact cache hit with improved performance
   */
  private async checkExactCacheHit(query: CAGQuery): Promise<CAGResult | null> {
    const cacheKey = this.generateCacheKey(query);
    const entry = this.cache.get(cacheKey);

    if (!entry) return null;

    // Check if cache entry is still valid
    const now = Date.now();
    if (now - entry.timestamp.getTime() > entry.ttl) {
      this.cache.delete(cacheKey);
      return null;
    }

    // Update access statistics
    entry.accessCount++;
    entry.lastAccessed = new Date();

    return {
      response: entry.response,
      confidence: entry.confidence,
      sources: entry.sources,
      techniques: entry.techniques,
      tools: entry.tools,
      codeExamples: entry.codeExamples,
      similarityScore: 1.0,
      cached: true,
      cacheHitType: 'exact',
      processingTime: 0,
      cacheSize: this.cache.size,
      memoryUsage: this.getMemoryUsage()
    };
  }

  /**
   * Check for similar cache hit with optimized similarity calculation
   */
  private async checkSimilarCacheHit(query: CAGQuery, threshold: number): Promise<CAGResult | null> {
    const queryEmbedding = await this.getQueryEmbedding(query.query);

    let bestMatch: { entry: CacheEntry; similarity: number } | null = null;
    const now = Date.now();

    // Use iterator for better performance with large caches
    for (const [key, entry] of this.cache.entries()) {
      // Skip if entry is expired
      if (now - entry.timestamp.getTime() > entry.ttl) {
        this.cache.delete(key);
        continue;
      }

      // Use cached similarity if available, otherwise calculate
      const similarity = this.calculateSimilarity(queryEmbedding, entry.queryEmbedding);

      if (similarity > threshold &&
        (!bestMatch || similarity > bestMatch.similarity)) {
        bestMatch = { entry, similarity };
      }
    }

    if (bestMatch) {
      bestMatch.entry.accessCount++;
      bestMatch.entry.lastAccessed = new Date();

      return {
        response: bestMatch.entry.response,
        confidence: bestMatch.entry.confidence,
        sources: bestMatch.entry.sources,
        techniques: bestMatch.entry.techniques,
        tools: bestMatch.entry.tools,
        codeExamples: bestMatch.entry.codeExamples,
        similarityScore: bestMatch.similarity,
        cached: true,
        cacheHitType: 'similar',
        processingTime: 0,
        cacheSize: this.cache.size,
        memoryUsage: this.getMemoryUsage()
      };
    }

    return null;
  }

  /**
   * Generate RAG response with enhanced prompt engineering
   */
  private async generateRAGResponse(query: CAGQuery): Promise<CAGResult> {
    const knowledgeResult = await this.knowledgeService.queryKnowledge({
      query: query.query,
      category: query.category,
      difficulty: query.difficulty,
      maxResults: query.maxResults ?? 15, // Increased for better coverage
      includeCode: query.includeCode,
      includeTechniques: query.includeTechniques
    });

    // Generate enhanced response using LLM with optimized prompt
    const enhancedPrompt = this.buildEnhancedPrompt(query, knowledgeResult);
    const response = await this.client.generate({
      prompt: enhancedPrompt,
      maxTokens: 2048, // Limit for faster responses
      temperature: 0.7 // Balanced creativity and consistency
    });

    return {
      response,
      confidence: knowledgeResult.confidence,
      sources: knowledgeResult.sources,
      techniques: knowledgeResult.techniques,
      tools: knowledgeResult.tools,
      codeExamples: knowledgeResult.codeExamples,
      cached: false,
      cacheHitType: 'none',
      processingTime: 0,
      cacheSize: this.cache.size,
      memoryUsage: this.getMemoryUsage()
    };
  }

  /**
   * Cache a new result with adaptive TTL and size management
   */
  private async cacheResult(query: CAGQuery, result: CAGResult): Promise<void> {
    const cacheKey = this.generateCacheKey(query);
    const queryEmbedding = await this.getQueryEmbedding(query.query);
    const contextHash = this.generateContextHash(query);

    // Calculate adaptive TTL based on query characteristics
    const baseTTL = this.defaultCacheTTL;
    const confidenceMultiplier = result.confidence;
    let priorityMultiplier: number;
    if (query.priority === 'high') {
      priorityMultiplier = 1.5;
    } else if (query.priority === 'low') {
      priorityMultiplier = 0.7;
    } else {
      priorityMultiplier = 1.0;
    }
    const adaptiveTTL = baseTTL * confidenceMultiplier * priorityMultiplier;

    const entry: CacheEntry = {
      response: result.response,
      timestamp: new Date(),
      accessCount: 1,
      queryEmbedding,
      contextHash,
      confidence: result.confidence,
      sources: result.sources,
      techniques: result.techniques,
      tools: result.tools,
      codeExamples: result.codeExamples,
      lastAccessed: new Date(),
      size: Buffer.byteLength(result.response, 'utf8'),
      ttl: adaptiveTTL
    };

    this.cache.set(cacheKey, entry);

    // Maintain cache size and memory usage
    await this.maintainCache();

    this.eventBus.emit('cag.cache.updated', {
      cacheSize: this.cache.size,
      cacheKey,
      confidence: result.confidence,
      memoryUsage: this.getMemoryUsage()
    });
  }

  /**
   * Enhanced cache maintenance with memory-aware eviction
   */
  private async maintainCache(): Promise<void> {
    const currentMemoryUsage = this.getMemoryUsage();

    // Check memory usage first
    if (currentMemoryUsage > this.maxMemoryUsage) {
      this.evictByMemoryUsage();
    }

    // Check cache size
    if (this.cache.size > this.maxCacheSize) {
      this.evictBySize();
    }
  }

  /**
   * Evict cache entries based on memory usage
   */
  private evictByMemoryUsage(): void {
    const entries = Array.from(this.cache.entries());

    // Sort by size (largest first) and access count (lowest first)
    entries.sort((a, b) => {
      if (a[1].size !== b[1].size) {
        return b[1].size - a[1].size; // Largest first
      }
      return a[1].accessCount - b[1].accessCount; // Least accessed first
    });

    let evictedCount = 0;
    const targetMemoryUsage = this.maxMemoryUsage * 0.8; // Target 80% of max

    for (const [key] of entries) {
      if (this.getMemoryUsage() <= targetMemoryUsage) break;
      this.cache.delete(key);
      evictedCount++;
      this.performanceMetrics.evictions++;
    }

    if (evictedCount > 0) {
      this.logger.info(`Memory-based eviction: removed ${evictedCount} entries`);
    }
  }

  /**
   * Evict cache entries based on size (LRU with access count)
   */
  private evictBySize(): void {
    const entries = Array.from(this.cache.entries());

    // Sort by access count and last accessed time (LRU)
    entries.sort((a, b) => {
      if (a[1].accessCount !== b[1].accessCount) {
        return a[1].accessCount - b[1].accessCount;
      }
      return a[1].lastAccessed.getTime() - b[1].lastAccessed.getTime();
    });

    const toRemove = entries.slice(0, entries.length - this.maxCacheSize);
    for (const [key] of toRemove) {
      this.cache.delete(key);
      this.performanceMetrics.evictions++;
    }

    if (toRemove.length > 0) {
      this.logger.info(`Size-based eviction: removed ${toRemove.length} entries`);
    }
  }

  /**
   * Get current memory usage in bytes
   */
  private getMemoryUsage(): number {
    let totalSize = 0;
    for (const entry of this.cache.values()) {
      totalSize += entry.size;
    }
    return totalSize;
  }

  /**
   * Update performance metrics
   */
  private updatePerformanceMetrics(responseTime: number, cached: boolean): void {
    this.responseTimes.push(responseTime);

    // Keep only recent response times
    if (this.responseTimes.length > this.maxResponseTimeHistory) {
      this.responseTimes.shift();
    }

    // Update average response time
    this.performanceMetrics.averageResponseTime =
      this.responseTimes.reduce((sum, time) => sum + time, 0) / this.responseTimes.length;

    // Update hit rate
    this.performanceMetrics.hitRate =
      this.performanceMetrics.totalQueries > 0
        ? (this.performanceMetrics.cacheHits / this.performanceMetrics.totalQueries) * 100
        : 0;

    // Update cache size and memory usage
    this.performanceMetrics.cacheSize = this.cache.size;
    this.performanceMetrics.memoryUsage = this.getMemoryUsage();
  }

  /**
   * Start periodic cache maintenance
   */
  private startCacheMaintenance(): void {
    setInterval(() => {
      this.performCacheMaintenance();
    }, 300000); // Every 5 minutes
  }

  /**
   * Perform periodic cache maintenance
   */
  private performCacheMaintenance(): void {
    const now = Date.now();
    let expiredCount = 0;

    for (const [key, entry] of this.cache.entries()) {
      if (now - entry.timestamp.getTime() > entry.ttl) {
        this.cache.delete(key);
        expiredCount++;
      }
    }

    if (expiredCount > 0) {
      this.logger.info(`Cache maintenance: removed ${expiredCount} expired entries`);
    }

    // Update performance metrics
    this.performanceMetrics.cacheSize = this.cache.size;
    this.performanceMetrics.memoryUsage = this.getMemoryUsage();
  }

  /**
   * Enhanced pre-warming with batch processing
   */
  async preWarmCache(commonQueries: string[]): Promise<void> {
    this.logger.info(`Pre-warming cache with ${commonQueries.length} queries`);

    const batches = this.chunkArray(commonQueries, this.prewarmBatchSize);
    let processedCount = 0;

    for (const batch of batches) {
      const promises = batch.map(async (query) => {
        try {
          await this.query({
            query,
            useCache: false, // Force generation for pre-warming
            priority: 'low' // Lower priority for pre-warming
          });
          processedCount++;
        } catch (error) {
          this.logger.warn(`Failed to pre-warm cache for query: ${query}`, error);
        }
      });

      await Promise.allSettled(promises);

      // Small delay between batches to avoid overwhelming the system
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    this.performanceMetrics.prewarmQueries = processedCount;
    this.logger.info(`Cache pre-warming completed: ${processedCount} queries processed`);
  }

  /**
   * Utility function to chunk array into batches
   */
  private chunkArray<T>(array: T[], size: number): T[][] {
    const chunks: T[][] = [];
    for (let i = 0; i < array.length; i += size) {
      chunks.push(array.slice(i, i + size));
    }
    return chunks;
  }

  /**
   * Get comprehensive performance metrics
   */
  getPerformanceMetrics(): CAGPerformanceMetrics {
    return { ...this.performanceMetrics };
  }

  /**
   * Get cache statistics with enhanced information
   */
  getCacheStats(): any {
    const hitRate = this.performanceMetrics.hitRate;
    const memoryUsageMB = this.performanceMetrics.memoryUsage / (1024 * 1024);

    return {
      ...this.performanceMetrics,
      hitRate: `${hitRate.toFixed(2)}%`,
      memoryUsageMB: `${memoryUsageMB.toFixed(2)} MB`,
      cacheSize: this.cache.size,
      embeddingCacheSize: this.embeddingCache.size,
      averageResponseTime: `${this.performanceMetrics.averageResponseTime.toFixed(2)}ms`
    };
  }

  /**
   * Generate cache key based on query and context
   */
  private generateCacheKey(query: CAGQuery): string {
    const contextStr = JSON.stringify(query.context ?? {});
    const categoryStr = query.category ?? '';
    const difficultyStr = query.difficulty ?? '';
    const priorityStr = query.priority ?? 'normal';

    return `${query.query}:${contextStr}:${categoryStr}:${difficultyStr}:${priorityStr}`;
  }

  /**
   * Get or compute query embedding
   */
  private async getQueryEmbedding(query: string): Promise<number[]> {
    if (this.embeddingCache.has(query)) {
      return this.embeddingCache.get(query)!;
    }

    // Check was moved to constructor and query method, but an explicit check here is still good defense.
    if (typeof this.client.embed !== 'function') {
      const errorMsg = "CRITICAL: LLMClient 'embed' method is not available in getQueryEmbedding. This should have been caught earlier.";
      this.logger.error(errorMsg);
      console.error(errorMsg);
      throw new Error(errorMsg);
    }

    const embedding = await this.client.embed(query);

    // Maintain embedding cache size
    if (this.embeddingCache.size >= this.embeddingCacheSize) {
      const firstKey = this.embeddingCache.keys().next().value;
      if (firstKey !== undefined) {
        this.embeddingCache.delete(firstKey);
      }
    }

    this.embeddingCache.set(query, embedding);
    return embedding;
  }

  /**
   * Calculate cosine similarity between two embeddings
   */
  private calculateSimilarity(embedding1: number[], embedding2: number[]): number {
    if (embedding1.length !== embedding2.length) {
      return 0;
    }

    let dotProduct = 0;
    let norm1 = 0;
    let norm2 = 0;

    for (let i = 0; i < embedding1.length; i++) {
      dotProduct += embedding1[i] * embedding2[i];
      norm1 += embedding1[i] * embedding1[i];
      norm2 += embedding2[i] * embedding2[i];
    }

    const similarity = dotProduct / (Math.sqrt(norm1) * Math.sqrt(norm2));
    return Math.max(0, Math.min(1, similarity));
  }

  /**
   * Generate context hash for similarity matching
   */
  private generateContextHash(query: CAGQuery): string {
    const crypto = require('crypto');
    const contextStr = JSON.stringify(query.context ?? {});
    return crypto.createHash('md5').update(contextStr).digest('hex');
  }

  /**
   * Build enhanced prompt for RAG generation
   */
  private buildEnhancedPrompt(query: CAGQuery, knowledgeResult: any): string {
    let prompt = `You are a cybersecurity expert assistant. Provide a comprehensive, accurate, and practical response to the following query:\n\n`;
    prompt += `Query: ${query.query}\n\n`;

    if (knowledgeResult.concepts && knowledgeResult.concepts.length > 0) {
      prompt += `Relevant cybersecurity knowledge:\n`;
      for (const concept of knowledgeResult.concepts.slice(0, 3)) {
        prompt += `- ${concept.name}: ${concept.description}\n`;
      }
      prompt += `\n`;
    }

    if (knowledgeResult.techniques && knowledgeResult.techniques.length > 0) {
      prompt += `Related techniques: ${knowledgeResult.techniques.join(', ')}\n\n`;
    }

    if (knowledgeResult.tools && knowledgeResult.tools.length > 0) {
      prompt += `Related tools: ${knowledgeResult.tools.join(', ')}\n\n`;
    }

    if (knowledgeResult.codeExamples && knowledgeResult.codeExamples.length > 0) {
      prompt += `Code examples:\n${knowledgeResult.codeExamples.slice(0, 2).join('\n')}\n\n`;
    }

    prompt += `Provide a detailed, practical response that includes:\n`;
    prompt += `1. Clear explanation of the concept\n`;
    prompt += `2. Practical implementation guidance\n`;
    prompt += `3. Security considerations\n`;
    prompt += `4. Related techniques and tools\n\n`;
    prompt += `Response:`;

    return prompt;
  }

  private generateQueryId(query: CAGQuery): string {
    const crypto = require('crypto');
    const queryStr = JSON.stringify(query);
    return crypto.createHash('md5').update(queryStr).digest('hex').substring(0, 8);
  }

  /**
   * Clear cache
   */
  clearCache(): void {
    this.cache.clear();
    this.embeddingCache.clear();
    // Reset all fields of performanceMetrics instead of reassigning
    this.performanceMetrics.totalQueries = 0;
    this.performanceMetrics.cacheHits = 0;
    this.performanceMetrics.cacheMisses = 0;
    this.performanceMetrics.averageResponseTime = 0;
    this.performanceMetrics.hitRate = 0;
    this.performanceMetrics.memoryUsage = 0;
    this.performanceMetrics.cacheSize = 0;
    this.performanceMetrics.evictions = 0;
    this.performanceMetrics.prewarmQueries = 0;
    this.logger.info('Cache cleared');
  }

  /**
   * Export cache for persistence
   */
  exportCache(): any {
    const cacheData: any = {};

    for (const [key, entry] of this.cache.entries()) {
      cacheData[key] = {
        response: entry.response,
        timestamp: entry.timestamp.toISOString(),
        accessCount: entry.accessCount,
        queryEmbedding: entry.queryEmbedding,
        contextHash: entry.contextHash,
        confidence: entry.confidence,
        sources: entry.sources,
        techniques: entry.techniques,
        tools: entry.tools,
        codeExamples: entry.codeExamples,
        lastAccessed: entry.lastAccessed.toISOString(),
        size: entry.size,
        ttl: entry.ttl
      };
    }

    return {
      cache: cacheData,
      stats: this.performanceMetrics
    };
  }

  /**
   * Import cache from persistence
   */
  importCache(cacheData: any): void {
    this.cache.clear();
    for (const [key, data] of Object.entries(cacheData.cache)) {
      const d = data as Record<string, any>;
      if (this.isValidCacheEntryData(d)) {
        const entry = this.parseCacheEntry(d);
        this.cache.set(key, entry);
      }
    }
    this.updatePerformanceMetricsFromStats(cacheData.stats);
    this.logger.info(`Imported ${this.cache.size} cache entries`);
  }

  private isValidCacheEntryData(d: Record<string, any>): boolean {
    return typeof d === 'object' && d !== null;
  }

  private parseCacheEntry(d: Record<string, any>): CacheEntry {
    return {
      response: typeof d.response === 'string' ? d.response : '',
      timestamp: new Date(typeof d.timestamp === 'string' ? d.timestamp : Date.now()),
      accessCount: typeof d.accessCount === 'number' ? d.accessCount : 0,
      queryEmbedding: Array.isArray(d.queryEmbedding) ? d.queryEmbedding : [],
      contextHash: typeof d.contextHash === 'string' ? d.contextHash : '',
      confidence: typeof d.confidence === 'number' ? d.confidence : 0,
      sources: Array.isArray(d.sources) ? d.sources : [],
      techniques: Array.isArray(d.techniques) ? d.techniques : [],
      tools: Array.isArray(d.tools) ? d.tools : [],
      codeExamples: Array.isArray(d.codeExamples) ? d.codeExamples : [],
      lastAccessed: new Date(typeof d.lastAccessed === 'string' ? d.lastAccessed : Date.now()),
      size: typeof d.size === 'number' ? d.size : 0,
      ttl: typeof d.ttl === 'number' ? d.ttl : 0
    };
  }

  private updatePerformanceMetricsFromStats(stats: any): void {
    if (!stats) return;
    this.performanceMetrics.totalQueries = stats.totalQueries ?? this.performanceMetrics.totalQueries;
    this.performanceMetrics.cacheHits = stats.cacheHits ?? this.performanceMetrics.cacheHits;
    this.performanceMetrics.cacheMisses = stats.cacheMisses ?? this.performanceMetrics.cacheMisses;
    this.performanceMetrics.averageResponseTime = stats.averageResponseTime ?? this.performanceMetrics.averageResponseTime;
    this.performanceMetrics.hitRate = stats.hitRate ?? this.performanceMetrics.hitRate;
    this.performanceMetrics.memoryUsage = stats.memoryUsage ?? this.performanceMetrics.memoryUsage;
    this.performanceMetrics.cacheSize = stats.cacheSize ?? this.performanceMetrics.cacheSize;
    this.performanceMetrics.evictions = stats.evictions ?? this.performanceMetrics.evictions;
    this.performanceMetrics.prewarmQueries = stats.prewarmQueries ?? this.performanceMetrics.prewarmQueries;
  }
}
