import crypto from 'crypto';
import fs from 'fs-extra';
import path from 'path';
import { EventBus } from '../events/event-bus';

export interface AuditLogEntry {
  timestamp: string;
  level: 'info' | 'warn' | 'error' | 'debug';
  actor: {
    type: 'user' | 'agent' | 'system';
    id?: string;
  };
  action: {
    type: string;
    details: any;
  };
  context?: any;
  result: 'success' | 'failure' | 'pending';
  errorMessage?: string;
}

export class AuditService {
  private readonly logFilePath: string;
  private readonly eventBus: EventBus;
  private readonly encryptionKey: Buffer;

  constructor(logDir: string, eventBus: EventBus, encryptionKey: string) {
    this.logFilePath = path.join(logDir, 'audit.log');
    this.eventBus = eventBus;
    this.encryptionKey = Buffer.from(encryptionKey, 'hex');
    fs.ensureFileSync(this.logFilePath);
    this.setupEventListeners();
  }

  private setupEventListeners() {
    this.eventBus.on('tool.execution.start', (data) => {
      this.log({
        level: 'info',
        actor: { type: 'agent' },
        action: {
          type: 'tool.execution.start',
          details: {
            tool: data.name,
            input: data.input,
          },
        },
        result: 'pending',
      });
    });

    this.eventBus.on('tool.execution.success', (data) => {
      this.log({
        level: 'info',
        actor: { type: 'agent' },
        action: {
          type: 'tool.execution.success',
          details: {
            tool: data.name,
            output: data.output,
          },
        },
        result: 'success',
      });
    });

    this.eventBus.on('tool.execution.error', (data) => {
      this.log({
        level: 'error',
        actor: { type: 'agent' },
        action: {
          type: 'tool.execution.error',
          details: {
            tool: data.name,
            input: data.input,
          },
        },
        result: 'failure',
        errorMessage: data.error.message,
      });
    });
  }

  private encrypt(text: string): string {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.encryptionKey, iv);
    const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return Buffer.concat([iv, authTag, encrypted]).toString('hex');
  }

  private decrypt(encryptedText: string): string {
    const data = Buffer.from(encryptedText, 'hex');
    const iv = data.slice(0, 16);
    const authTag = data.slice(16, 32);
    const encrypted = data.slice(32);
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.encryptionKey, iv);
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    return decrypted.toString('utf8');
  }

  public async log(entry: Omit<AuditLogEntry, 'timestamp'>): Promise<void> {
    const logEntry: AuditLogEntry = {
      timestamp: new Date().toISOString(),
      ...entry,
    };

    const logLine = JSON.stringify(logEntry);
    const encryptedLogLine = this.encrypt(logLine) + '\n';
    await fs.appendFile(this.logFilePath, encryptedLogLine);
  }

  public async queryLogs(filter: Partial<AuditLogEntry>): Promise<AuditLogEntry[]> {
    // TODO: CRITICAL PERFORMANCE BOTTLENECK - Reading and decrypting the entire log file for every query.
    // This will not scale. Consider:
    // 1. Using a proper logging database/system (ELK, Splunk).
    // 2. If file-based, implement indexing (e.g., by date) and allow range queries.
    // 3. Stream-process the file, decrypting and filtering line-by-line, especially for targeted queries.
    // 4. For now, this implementation remains but is unsuitable for production with large logs.

    const logContent = await fs.readFile(this.logFilePath, 'utf-8');
    if (!logContent) {
      return [];
    }

    const lines = logContent.trim().split('\n');
    const allLogs: AuditLogEntry[] = [];
    for (const line of lines) {
      if (line.trim() === '') continue;
      try {
        allLogs.push(JSON.parse(this.decrypt(line)) as AuditLogEntry);
      } catch (e: any) {
        console.warn(`AuditService: Failed to decrypt or parse log line. Skipping. Error: ${e.message}`);
        // Optionally, store corrupted lines elsewhere for investigation
      }
    }

    if (Object.keys(filter).length === 0) {
      return allLogs;
    }

    return allLogs.filter(log => {
      return Object.entries(filter).every(([key, value]) => {
        return log[key as keyof AuditLogEntry] === value;
      });
    });
  }
}
