import { LogAnalyzerClient } from '../clients/log-analyzer-client';
import { Logger } from '../utils/logger';
import { AuditService } from './audit-service';

export class LogAnalysisService {
  private readonly logAnalyzerClient: LogAnalyzerClient;
  private readonly auditService: AuditService;
  private readonly logger: Logger;

  constructor(logAnalyzerClient: LogAnalyzerClient, auditService: AuditService, logger: Logger) {
    this.logAnalyzerClient = logAnalyzerClient;
    this.auditService = auditService;
    this.logger = logger;
  }

  public async analyzeAuditLogs(filters?: Partial<any>): Promise<any> { // Added filters parameter
    try {
      this.logger.info('Fetching audit logs for analysis...');
      // TODO: Pass filters to auditService.queryLogs once it supports them.
      // For now, it still fetches all logs, which is a performance issue.
      const logs = await this.auditService.queryLogs(filters || {});
      if (logs.length === 0) {
        this.logger.info('No audit logs to analyze with the given filters.');
        return [];
      }

      this.logger.info(`Analyzing ${logs.length} log entries...`);
      const analysisResult = await this.logAnalyzerClient.analyze(logs);
      this.logger.info('Log analysis complete.');

      // You can add more logic here to handle the results,
      // like sending alerts or storing the results.

      return analysisResult;
    } catch (error) {
      this.logger.error('Error during log analysis:', error);
      throw error;
    }
  }
}
