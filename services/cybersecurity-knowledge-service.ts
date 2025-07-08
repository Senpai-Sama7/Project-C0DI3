import * as fs from 'fs-extra';
import * as path from 'path';
import { EventBus } from '../events/event-bus';
import { Logger } from '../utils/logger';
import { MemorySystem } from '../memory/memory-system';
import { LLMClient } from '../types';

export interface CybersecurityConcept {
  id: string;
  name: string;
  description: string;
  category: 'red-team' | 'blue-team' | 'general' | 'tools' | 'techniques' | 'defense';
  source: string;
  content: string;
  metadata: {
    chapter?: string;
    page?: string;
    difficulty?: 'beginner' | 'intermediate' | 'advanced';
    tools?: string[];
    techniques?: string[];
    codeExamples?: string[];
  };
  embedding?: number[];
  relatedConcepts: string[];
  confidence: number;
  lastUpdated: number;
}

export interface KnowledgeQuery {
  query: string;
  category?: string;
  difficulty?: string;
  maxResults?: number;
  includeCode?: boolean;
  includeTechniques?: boolean;
}

export interface KnowledgeResult {
  concepts: CybersecurityConcept[];
  techniques: string[];
  tools: string[];
  codeExamples: string[];
  confidence: number;
  sources: string[];
}

export class CybersecurityKnowledgeService {
  private readonly memory: MemorySystem;
  private readonly client: LLMClient;
  private readonly eventBus: EventBus;
  private readonly logger: Logger;
  private readonly booksPath: string;
  private readonly concepts: Map<string, CybersecurityConcept> = new Map();
  private readonly techniques: Map<string, string[]> = new Map();
  private readonly tools: Map<string, string[]> = new Map();

  constructor(
    memory: MemorySystem,
    client: LLMClient,
    eventBus: EventBus,
    booksPath: string = './memory/cybersecurity-books'
  ) {
    this.memory = memory;
    this.client = client;
    this.eventBus = eventBus;
    this.logger = new Logger('CybersecurityKnowledgeService');
    this.booksPath = booksPath;

    if (typeof this.client.embed !== 'function') {
      const errorMsg = "CRITICAL: LLMClient does not have a functional 'embed' method. CybersecurityKnowledgeService semantic features will be severely impaired or non-functional.";
      this.logger.error(errorMsg);
      console.error(errorMsg);
      // Consider not throwing here to allow service to start with degraded functionality,
      // but core features like semantic search will fail.
    }
  }

  /**
   * Initialize the cybersecurity knowledge service
   */
  async initialize(): Promise<void> {
    this.logger.info('Initializing Cybersecurity Knowledge Service...');

    try {
      // Load and process all cybersecurity books
      await this.loadCybersecurityBooks();

      if (typeof this.client.embed === 'function') {
        // Create embeddings for all concepts
        await this.createConceptEmbeddings();
        // Build relationships between concepts
        await this.buildConceptRelationships();
      } else {
        this.logger.warn("Skipping concept embeddings and relationship building as LLMClient 'embed' method is not available.");
      }

      this.logger.info(`Loaded ${this.concepts.size} cybersecurity concepts`);
      this.eventBus.emit('cybersecurity-knowledge.initialized', {
        conceptCount: this.concepts.size,
        techniqueCount: this.techniques.size,
        toolCount: this.tools.size
      });
    } catch (error) {
      this.logger.error('Failed to initialize cybersecurity knowledge service:', error);
      throw error;
    }
  }

  /**
   * Load and process cybersecurity books from JSON files
   */
  private async loadCybersecurityBooks(): Promise<void> {
    const bookFiles = await fs.readdir(this.booksPath);

    for (const file of bookFiles) {
      if (file.endsWith('.json')) {
        await this.processBookFile(path.join(this.booksPath, file));
      }
    }
  }

  /**
   * Process a single cybersecurity book file
   */
  private async processBookFile(filePath: string): Promise<void> {
    this.logger.info(`Processing book: ${path.basename(filePath)}`);

    try {
      const bookData = await fs.readJson(filePath);
      const bookName = path.basename(filePath, '.json');

      if (bookData.content_blocks) {
        await this.extractConceptsFromBook(bookData.content_blocks, bookName);
      }
    } catch (error) {
      this.logger.error(`Failed to process book ${filePath}:`, error);
    }
  }

  /**
   * Extract cybersecurity concepts from book content blocks
   */
  private async extractConceptsFromBook(contentBlocks: any[], bookName: string): Promise<void> {
    for (const block of contentBlocks) {
      if (block.type === 'paragraph' || block.type === 'heading') {
        const concept = await this.extractConceptFromBlock(block, bookName);
        if (concept) {
          this.concepts.set(concept.id, concept);
        }
      }
    }
  }

  /**
   * Extract a cybersecurity concept from a content block
   */
  private async extractConceptFromBlock(block: any, bookName: string): Promise<CybersecurityConcept | null> {
    const content = block.content;
    if (!content || content.length < 10) return null;

    // Use LLM to analyze the content and extract cybersecurity concepts
    const analysis = await this.analyzeContentForConcepts(content, bookName);

    if (analysis.concepts.length === 0) return null;

    const concept = analysis.concepts[0]; // Take the primary concept
    const conceptId = `concept-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;

    return {
      id: conceptId,
      name: concept.name,
      description: concept.description,
      category: concept.category,
      source: bookName,
      content: content,
      metadata: {
        chapter: block.metadata?.chapter,
        page: block.metadata?.page,
        difficulty: concept.difficulty,
        tools: concept.tools,
        techniques: concept.techniques,
        codeExamples: concept.codeExamples
      },
      relatedConcepts: [],
      confidence: concept.confidence,
      lastUpdated: Date.now()
    };
  }

  /**
   * Use LLM to analyze content and extract cybersecurity concepts
   */
  private async analyzeContentForConcepts(content: string, bookName: string): Promise<{
    concepts: Array<{
      name: string;
      description: string;
      category: 'red-team' | 'blue-team' | 'general' | 'tools' | 'techniques' | 'defense';
      difficulty: 'beginner' | 'intermediate' | 'advanced';
      tools: string[];
      techniques: string[];
      codeExamples: string[];
      confidence: number;
    }>;
  }> {
    const prompt = `
      Analyze the following cybersecurity content and extract relevant concepts, techniques, tools, and code examples.

      Content: ${content}
      Source: ${bookName}

      Return a JSON object with the following structure:
      {
        "concepts": [
          {
            "name": "concept name",
            "description": "brief description",
            "category": "red-team|blue-team|general|tools|techniques|defense",
            "difficulty": "beginner|intermediate|advanced",
            "tools": ["tool1", "tool2"],
            "techniques": ["technique1", "technique2"],
            "codeExamples": ["code example 1", "code example 2"],
            "confidence": 0.0-1.0
          }
        ]
      }

      Only return concepts that are clearly cybersecurity-related. If no relevant concepts are found, return an empty concepts array.
    `;

    try {
      const response = await this.client.generate({ prompt });
      const result = JSON.parse(response);

      // Validate and sanitize the response
      if (result.concepts && Array.isArray(result.concepts)) {
        result.concepts = result.concepts.map((concept: any) => ({
          ...concept,
          category: this.validateCategory(concept.category),
          difficulty: this.validateDifficulty(concept.difficulty)
        }));
      }

      return result;
    } catch (error) {
      this.logger.warn('Failed to analyze content for concepts:', error);
      return { concepts: [] };
    }
  }

  private validateCategory(category: string): 'red-team' | 'blue-team' | 'general' | 'tools' | 'techniques' | 'defense' {
    const validCategories = ['red-team', 'blue-team', 'general', 'tools', 'techniques', 'defense'];
    return validCategories.includes(category) ? category as any : 'general';
  }

  private validateDifficulty(difficulty: string): 'beginner' | 'intermediate' | 'advanced' {
    const validDifficulties = ['beginner', 'intermediate', 'advanced'];
    return validDifficulties.includes(difficulty) ? difficulty as any : 'intermediate';
  }

  /**
   * Create embeddings for all cybersecurity concepts
   */
  private async createConceptEmbeddings(): Promise<void> {
    this.logger.info('Creating embeddings for cybersecurity concepts...');

    for (const concept of this.concepts.values()) {
      try {
        const embeddingText = `${concept.name} ${concept.description} ${concept.content}`;
        if (this.client && this.client.embed) {
          concept.embedding = await this.client.embed(embeddingText);
        }
      } catch (error) {
        this.logger.warn(`Failed to create embedding for concept ${concept.name}:`, error);
      }
    }
  }

  /**
   * Build relationships between cybersecurity concepts
   */
  private async buildConceptRelationships(): Promise<void> {
    this.logger.info('Building concept relationships...');
    // TODO: PERFORMANCE - This is an N^2 operation (findRelatedConcepts iterates all other concepts).
    // For a large number of concepts, this will be extremely slow.
    // Consider using an Approximate Nearest Neighbor (ANN) search index (e.g., from a VectorStore)
    // or batching/optimizing this process significantly if concept count is high.
    // For now, proceeding with the existing logic but acknowledging the performance concern.

    for (const concept of this.concepts.values()) {
      const related = await this.findRelatedConcepts(concept);
      concept.relatedConcepts = related.map(c => c.id);
    }
  }

  /**
   * Find related concepts for a given concept
   */
  private async findRelatedConcepts(concept: CybersecurityConcept): Promise<CybersecurityConcept[]> {
    // TODO: PERFORMANCE - This iterates all other concepts. See note in buildConceptRelationships.
    const related: CybersecurityConcept[] = [];

    for (const otherConcept of this.concepts.values()) {
      if (otherConcept.id === concept.id) continue;

      // Ensure embeddings exist for both concepts before calculating similarity
      if (!concept.embedding || !otherConcept.embedding) continue;

      const similarity = await this.calculateConceptSimilarity(concept, otherConcept);
      if (similarity > 0.7) { // Similarity threshold
        related.push(otherConcept);
      }
    }

    // Sort by similarity (descending) before slicing, if score is available and needed for top N
    // This example assumes calculateConceptSimilarity returns a score that can be used for sorting.
    // If not, the simple push and slice is fine for a basic implementation.
    // related.sort((a, b) => b.score - a.score); // Assuming concept objects get a temporary score property

    return related.slice(0, 5); // Limit to top 5 related concepts
  }

  /**
   * Calculate similarity between two concepts
   */
  private async calculateConceptSimilarity(concept1: CybersecurityConcept, concept2: CybersecurityConcept): Promise<number> {
    if (!concept1.embedding || !concept2.embedding) return 0;

    // Simple cosine similarity calculation
    const dotProduct = concept1.embedding.reduce((sum, val, i) => sum + val * (concept2.embedding?.[i] || 0), 0);
    const magnitude1 = Math.sqrt(concept1.embedding.reduce((sum, val) => sum + val * val, 0));
    const magnitude2 = Math.sqrt((concept2.embedding || []).reduce((sum, val) => sum + val * val, 0));

    return magnitude1 && magnitude2 ? dotProduct / (magnitude1 * magnitude2) : 0;
  }

  /**
   * Query cybersecurity knowledge based on user input
   */
  async queryKnowledge(query: KnowledgeQuery): Promise<KnowledgeResult> {
    this.logger.debug(`Querying cybersecurity knowledge: ${query.query}`);

    try {
      // Find relevant concepts using semantic search
      const relevantConcepts = await this.findRelevantConcepts(query);

      // Extract techniques, tools, and code examples
      const techniques = this.extractTechniques(relevantConcepts);
      const tools = this.extractTools(relevantConcepts);
      const codeExamples = this.extractCodeExamples(relevantConcepts);

      // Calculate overall confidence
      const confidence = relevantConcepts.length > 0
        ? relevantConcepts.reduce((sum, c) => sum + c.confidence, 0) / relevantConcepts.length
        : 0;

      const sources = [...new Set(relevantConcepts.map(c => c.source))];

      return {
        concepts: relevantConcepts,
        techniques,
        tools,
        codeExamples,
        confidence,
        sources
      };
    } catch (error) {
      this.logger.error('Failed to query cybersecurity knowledge:', error);
      throw error;
    }
  }

  /**
   * Find relevant concepts using semantic search
   */
  private async findRelevantConcepts(query: KnowledgeQuery): Promise<CybersecurityConcept[]> {
    if (typeof this.client.embed !== 'function') {
      this.logger.error("CybersecurityKnowledgeService.findRelevantConcepts: LLMClient 'embed' method is not available. Cannot perform semantic search.");
      // Fallback: could attempt a keyword search or return empty.
      return [];
    }

    const queryEmbedding = await this.client.embed(query.query);
    const relevant: Array<{ concept: CybersecurityConcept; score: number }> = [];

    for (const concept of this.concepts.values()) {
      if (!concept.embedding) continue;

      // Apply filters
      if (query.category && concept.category !== query.category) continue;
      if (query.difficulty && concept.metadata.difficulty !== query.difficulty) continue;

      // Calculate similarity
      const similarity = await this.calculateSimilarity(queryEmbedding, concept.embedding);
      if (similarity > 0.3) { // Threshold for relevance
        relevant.push({ concept, score: similarity });
      }
    }

    // Sort by relevance and return top results
    return relevant
      .sort((a, b) => b.score - a.score)
      .slice(0, query.maxResults || 10)
      .map(r => r.concept);
  }

  /**
   * Calculate similarity between query embedding and concept embedding
   */
  private async calculateSimilarity(queryEmbedding: number[], conceptEmbedding: number[]): Promise<number> {
    const dotProduct = queryEmbedding.reduce((sum, val, i) => sum + val * conceptEmbedding[i], 0);
    const magnitude1 = Math.sqrt(queryEmbedding.reduce((sum, val) => sum + val * val, 0));
    const magnitude2 = Math.sqrt(conceptEmbedding.reduce((sum, val) => sum + val * val, 0));

    return dotProduct / (magnitude1 * magnitude2);
  }

  /**
   * Extract techniques from relevant concepts
   */
  private extractTechniques(concepts: CybersecurityConcept[]): string[] {
    const techniques = new Set<string>();

    for (const concept of concepts) {
      if (concept.metadata.techniques) {
        concept.metadata.techniques.forEach(t => techniques.add(t));
      }
    }

    return Array.from(techniques);
  }

  /**
   * Extract tools from relevant concepts
   */
  private extractTools(concepts: CybersecurityConcept[]): string[] {
    const tools = new Set<string>();

    for (const concept of concepts) {
      if (concept.metadata.tools) {
        concept.metadata.tools.forEach(t => tools.add(t));
      }
    }

    return Array.from(tools);
  }

  /**
   * Extract code examples from relevant concepts
   */
  private extractCodeExamples(concepts: CybersecurityConcept[]): string[] {
    const codeExamples = new Set<string>();

    for (const concept of concepts) {
      if (concept.metadata.codeExamples) {
        concept.metadata.codeExamples.forEach(c => codeExamples.add(c));
      }
    }

    return Array.from(codeExamples);
  }

  /**
   * Get concept by ID
   */
  getConcept(id: string): CybersecurityConcept | undefined {
    return this.concepts.get(id);
  }

  /**
   * Get all concepts
   */
  getAllConcepts(): CybersecurityConcept[] {
    return Array.from(this.concepts.values());
  }

  /**
   * Get concepts by category
   */
  getConceptsByCategory(category: string): CybersecurityConcept[] {
    return Array.from(this.concepts.values()).filter(c => c.category === category);
  }

  /**
   * Get statistics about the knowledge base
   */
  getKnowledgeStatistics(): {
    totalConcepts: number;
    conceptsByCategory: Record<string, number>;
    conceptsByDifficulty: Record<string, number>;
    totalTechniques: number;
    totalTools: number;
  } {
    const conceptsByCategory: Record<string, number> = {};
    const conceptsByDifficulty: Record<string, number> = {};

    for (const concept of this.concepts.values()) {
      conceptsByCategory[concept.category] = (conceptsByCategory[concept.category] || 0) + 1;
      if (concept.metadata.difficulty) {
        conceptsByDifficulty[concept.metadata.difficulty] = (conceptsByDifficulty[concept.metadata.difficulty] || 0) + 1;
      }
    }

    const totalTechniques = this.extractTechniques(Array.from(this.concepts.values())).length;
    const totalTools = this.extractTools(Array.from(this.concepts.values())).length;

    return {
      totalConcepts: this.concepts.size,
      conceptsByCategory,
      conceptsByDifficulty,
      totalTechniques,
      totalTools
    };
  }
}
