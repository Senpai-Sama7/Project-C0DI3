import fs from 'fs-extra';
import path from 'path';
import { DocumentChunk, VectorStore } from '../memory/vector-store';

export class BookIngestionService {
  private readonly vectorStore: VectorStore;

  constructor(vectorStore: VectorStore) {
    this.vectorStore = vectorStore;
  }

  public async ingestBook(filePath: string): Promise<void> {
    // TODO: SECURITY - Add path validation and sanitization for filePath if it can come from an untrusted source.
    // Ensure it's restricted to a predefined books directory to prevent path traversal.
    // Example (conceptual - actual validation depends on security model):
    // const allowedBooksDirectory = path.resolve('./data/books_to_ingest');
    // const resolvedFilePath = path.resolve(filePath);
    // if (!resolvedFilePath.startsWith(allowedBooksDirectory)) {
    //   throw new Error('Access denied: filePath is outside the allowed directory.');
    // }
    // For now, proceeding with the assumption that filePath is trusted or validated by the caller.
    console.log(`Ingesting book from: ${filePath}`);
    const text = await fs.readFile(filePath, 'utf-8');

    // Simple chunking strategy (by paragraph)
    const chunks = text.split(/\n\s*\n/);

    const documents: DocumentChunk[] = chunks.map((chunk, index) => ({
      id: `${path.basename(filePath)}-${index}`,
      text: chunk,
      metadata: {
        source: filePath,
      },
    }));

    await this.vectorStore.addDocuments(documents);
    console.log(`Successfully ingested ${documents.length} chunks from ${filePath}`);
  }
}
