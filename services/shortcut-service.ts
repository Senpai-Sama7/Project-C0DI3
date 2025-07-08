import { EventBus } from '../events/event-bus';
import { Logger } from '../utils/logger';
import * as fs from 'fs';
import * as path from 'path';

export interface Shortcut {
  name: string;
  description: string;
  command: string;
  category: 'system' | 'security' | 'tools' | 'learning' | 'custom';
  aliases: string[];
  requiresAuth: boolean;
  permissions?: string[];
  naturalLanguage?: string;
  examples: string[];
}

export interface ShortcutExecution {
  shortcut: Shortcut;
  args: string[];
  result: any;
  executionTime: number;
  success: boolean;
  error?: string;
}

export class ShortcutService {
  private readonly eventBus: EventBus;
  private readonly logger: Logger;
  private shortcuts: Map<string, Shortcut> = new Map();
  private readonly shortcutsFile: string;
  private readonly defaultShortcuts: Shortcut[] = [
    {
      name: 'health',
      description: 'Check system health and status',
      command: 'system health check',
      category: 'system',
      aliases: ['h', 'status', 'check'],
      requiresAuth: true,
      permissions: ['system:read'],
      naturalLanguage: 'Check system health',
      examples: ['health', 'h', 'system status']
    },
    {
      name: 'scan',
      description: 'Run network scan with nmap',
      command: 'run nmap scan',
      category: 'security',
      aliases: ['nmap', 'network-scan'],
      requiresAuth: true,
      permissions: ['tools:execute'],
      naturalLanguage: 'Scan network for vulnerabilities',
      examples: ['scan 192.168.1.0/24', 'nmap localhost', 'network scan']
    },
    {
      name: 'explain',
      description: 'Explain cybersecurity concept',
      command: 'explain concept',
      category: 'learning',
      aliases: ['what', 'how', 'info'],
      requiresAuth: false,
      naturalLanguage: 'Explain a cybersecurity topic',
      examples: ['explain SQL injection', 'what is phishing', 'how to detect malware']
    },
    {
      name: 'learn',
      description: 'Start learning mission',
      command: 'start learning mission',
      category: 'learning',
      aliases: ['training', 'mission'],
      requiresAuth: true,
      permissions: ['learning:access'],
      naturalLanguage: 'Start cybersecurity training',
      examples: ['learn', 'training', 'start mission']
    },
    {
      name: 'logs',
      description: 'Analyze security logs',
      command: 'analyze logs for threats',
      category: 'security',
      aliases: ['audit', 'log-analysis'],
      requiresAuth: true,
      permissions: ['logs:read'],
      naturalLanguage: 'Analyze security logs',
      examples: ['logs', 'audit logs', 'log analysis']
    },
    {
      name: 'tools',
      description: 'List available security tools',
      command: 'list available tools',
      category: 'tools',
      aliases: ['list-tools', 'available'],
      requiresAuth: true,
      permissions: ['tools:read'],
      naturalLanguage: 'Show available security tools',
      examples: ['tools', 'list tools', 'available tools']
    },
    {
      name: 'query',
      description: 'Query cybersecurity knowledge',
      command: 'query cybersecurity knowledge',
      category: 'learning',
      aliases: ['q', 'search', 'find'],
      requiresAuth: false,
      naturalLanguage: 'Search cybersecurity knowledge',
      examples: ['query SQL injection', 'q phishing', 'search malware']
    },
    {
      name: 'stats',
      description: 'Show system statistics',
      command: 'show system statistics',
      category: 'system',
      aliases: ['statistics', 'metrics'],
      requiresAuth: true,
      permissions: ['system:read'],
      naturalLanguage: 'Show system statistics',
      examples: ['stats', 'statistics', 'metrics']
    },
    {
      name: 'help',
      description: 'Show help and available commands',
      command: 'show help',
      category: 'system',
      aliases: ['h', '?', 'commands'],
      requiresAuth: false,
      naturalLanguage: 'Show help information',
      examples: ['help', 'h', 'commands', '?']
    },
    {
      name: 'clear',
      description: 'Clear terminal screen',
      command: 'clear screen',
      category: 'system',
      aliases: ['cls', 'clean'],
      requiresAuth: false,
      naturalLanguage: 'Clear the screen',
      examples: ['clear', 'cls', 'clean']
    },
    {
      name: 'logout',
      description: 'Logout current user',
      command: 'logout user',
      category: 'system',
      aliases: ['signout', 'exit'],
      requiresAuth: true,
      naturalLanguage: 'Logout from the system',
      examples: ['logout', 'signout', 'exit']
    },
    {
      name: 'version',
      description: 'Show version information',
      command: 'show version',
      category: 'system',
      aliases: ['v', 'ver'],
      requiresAuth: false,
      naturalLanguage: 'Show version information',
      examples: ['version', 'v', 'ver']
    }
  ];

  constructor(eventBus: EventBus) {
    this.eventBus = eventBus;
    this.logger = new Logger('ShortcutService');
    this.shortcutsFile = path.join(process.cwd(), 'data', 'shortcuts.json');

    this.loadShortcuts();
    this.initializeDefaultShortcuts();

    this.logger.info('ShortcutService initialized');
  }

  /**
   * Load shortcuts from file
   */
  private loadShortcuts(): void {
    try {
      if (fs.existsSync(this.shortcutsFile)) {
        const data = fs.readFileSync(this.shortcutsFile, 'utf8');
        const shortcutsData = JSON.parse(data);

        for (const shortcutData of shortcutsData) {
          const shortcut: Shortcut = {
            ...shortcutData,
            aliases: shortcutData.aliases || [],
            examples: shortcutData.examples || []
          };
          this.shortcuts.set(shortcut.name, shortcut);
        }
      }
    } catch (error) {
      this.logger.error('Failed to load shortcuts', error);
    }
  }

  /**
   * Save shortcuts to file
   */
  private saveShortcuts(): void {
    try {
      const shortcutsData = Array.from(this.shortcuts.values());
      const dir = path.dirname(this.shortcutsFile);

      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }

      fs.writeFileSync(this.shortcutsFile, JSON.stringify(shortcutsData, null, 2));
    } catch (error) {
      this.logger.error('Failed to save shortcuts', error);
    }
  }

  /**
   * Initialize default shortcuts
   */
  private initializeDefaultShortcuts(): void {
    for (const shortcut of this.defaultShortcuts) {
      if (!this.shortcuts.has(shortcut.name)) {
        this.shortcuts.set(shortcut.name, shortcut);
      }
    }
    this.saveShortcuts();
  }

  /**
   * Find shortcut by name or alias
   */
  findShortcut(input: string): Shortcut | null {
    const normalizedInput = input.toLowerCase().trim();

    // Direct name match
    if (this.shortcuts.has(normalizedInput)) {
      return this.shortcuts.get(normalizedInput)!;
    }

    // Alias match
    for (const shortcut of this.shortcuts.values()) {
      if (shortcut.aliases.includes(normalizedInput)) {
        return shortcut;
      }
    }

    // Partial match
    for (const shortcut of this.shortcuts.values()) {
      if (shortcut.name.includes(normalizedInput) ||
          shortcut.aliases.some(alias => alias.includes(normalizedInput))) {
        return shortcut;
      }
    }

    return null;
  }

  /**
   * Execute a shortcut
   */
  async executeShortcut(shortcutName: string, args: string[] = [], context?: any): Promise<ShortcutExecution> {
    const startTime = Date.now();
    const shortcut = this.findShortcut(shortcutName);

    if (!shortcut) {
      return {
        shortcut: { name: shortcutName, description: '', command: '', category: 'custom', aliases: [], requiresAuth: false, examples: [] },
        args,
        result: null,
        executionTime: Date.now() - startTime,
        success: false,
        error: `Shortcut '${shortcutName}' not found`
      };
    }

    try {
      // Check authentication if required
      if (shortcut.requiresAuth && (!context?.user || !context?.session)) {
         // TODO: Integrate with AuthService.verifyToken(context.token) if a token is passed in context
         // For now, assuming if context.user is not present, auth has failed or was not performed.
        throw new Error(`Shortcut '${shortcut.name}' requires authentication. User not authenticated.`);
      }

      // TODO: Implement permission checking using AuthService.checkPermission
      // if (shortcut.permissions && context?.user) {
      //   const authService = context.authService; // Assuming AuthService instance is passed in context
      //   if (authService) {
      //     let hasRequiredPermission = false;
      //     for (const perm of shortcut.permissions) {
      //        // Assuming perm is like "resource:action" e.g., "tools:execute"
      //        const [resource, action] = perm.split(':');
      //        if (await authService.checkPermission(context.user.id, resource, action)) {
      //          hasRequiredPermission = true;
      //          break;
      //        }
      //     }
      //     if (!hasRequiredPermission) {
      //       throw new Error(`User does not have required permissions for shortcut '${shortcut.name}'. Required: ${shortcut.permissions.join(', ')}`);
      //     }
      //   } else {
      //       this.logger.warn(`AuthService not found in context for shortcut '${shortcut.name}'. Cannot verify permissions.`);
      //       // Depending on policy, could throw error here or proceed with caution.
      //   }
      // }
      this.logger.warn(`ShortcutService.executeShortcut: Permission check for shortcut '${shortcut.name}' is currently a TODO. Enforce permissions using AuthService.`);


      // Execute the command
      const result = await this.executeCommand(shortcut.command, args, context);

      const execution: ShortcutExecution = {
        shortcut,
        args,
        result,
        executionTime: Date.now() - startTime,
        success: true
      };

      // Log execution
      this.eventBus.emit('shortcut.executed', execution);

      return execution;

    } catch (error) {
      const execution: ShortcutExecution = {
        shortcut,
        args,
        result: null,
        executionTime: Date.now() - startTime,
        success: false,
        error: error.message
      };

      this.logger.error(`Shortcut execution failed: ${shortcutName}`, error);
      this.eventBus.emit('shortcut.failed', execution);

      return execution;
    }
  }

  /**
   * Execute the actual command
   */
  private async executeCommand(command: string, args: string[], context?: any): Promise<any> {
    // This would integrate with your existing command execution system
    // For now, we'll return a structured response

    const fullCommand = `${command} ${args.join(' ')}`.trim();

    return {
      command: fullCommand,
      type: 'shortcut',
      timestamp: new Date().toISOString(),
      context
    };
  }

  /**
   * Add a new shortcut
   */
  addShortcut(shortcut: Shortcut): boolean {
    try {
      this.shortcuts.set(shortcut.name, shortcut);
      this.saveShortcuts();

      this.eventBus.emit('shortcut.added', shortcut);
      this.logger.info(`Shortcut added: ${shortcut.name}`);

      return true;
    } catch (error) {
      this.logger.error(`Failed to add shortcut: ${shortcut.name}`, error);
      return false;
    }
  }

  /**
   * Remove a shortcut
   */
  removeShortcut(name: string): boolean {
    try {
      const shortcut = this.shortcuts.get(name);
      if (shortcut) {
        this.shortcuts.delete(name);
        this.saveShortcuts();

        this.eventBus.emit('shortcut.removed', shortcut);
        this.logger.info(`Shortcut removed: ${name}`);

        return true;
      }
      return false;
    } catch (error) {
      this.logger.error(`Failed to remove shortcut: ${name}`, error);
      return false;
    }
  }

  /**
   * Update a shortcut
   */
  updateShortcut(name: string, updates: Partial<Shortcut>): boolean {
    try {
      const shortcut = this.shortcuts.get(name);
      if (shortcut) {
        const updatedShortcut = { ...shortcut, ...updates };
        this.shortcuts.set(name, updatedShortcut);
        this.saveShortcuts();

        this.eventBus.emit('shortcut.updated', updatedShortcut);
        this.logger.info(`Shortcut updated: ${name}`);

        return true;
      }
      return false;
    } catch (error) {
      this.logger.error(`Failed to update shortcut: ${name}`, error);
      return false;
    }
  }

  /**
   * List all shortcuts
   */
  listShortcuts(category?: string): Shortcut[] {
    const shortcuts = Array.from(this.shortcuts.values());

    if (category) {
      return shortcuts.filter(s => s.category === category);
    }

    return shortcuts;
  }

  /**
   * Get shortcuts by category
   */
  getShortcutsByCategory(category: string): Shortcut[] {
    return this.listShortcuts(category);
  }

  /**
   * Search shortcuts
   */
  searchShortcuts(query: string): Shortcut[] {
    const normalizedQuery = query.toLowerCase();
    const results: Shortcut[] = [];

    for (const shortcut of this.shortcuts.values()) {
      if (shortcut.name.toLowerCase().includes(normalizedQuery) ||
          shortcut.description.toLowerCase().includes(normalizedQuery) ||
          shortcut.aliases.some(alias => alias.toLowerCase().includes(normalizedQuery)) ||
          shortcut.naturalLanguage?.toLowerCase().includes(normalizedQuery)) {
        results.push(shortcut);
      }
    }

    return results;
  }

  /**
   * Get help for shortcuts
   */
  getHelp(): string {
    const categories = ['system', 'security', 'tools', 'learning', 'custom'];
    let help = '🔧 Available Shortcuts\n';
    help += '=====================\n\n';

    for (const category of categories) {
      const shortcuts = this.getShortcutsByCategory(category);
      if (shortcuts.length > 0) {
        help += `📁 ${category.toUpperCase()}\n`;
        help += '-'.repeat(category.length + 8) + '\n';

        for (const shortcut of shortcuts) {
          help += `  ${shortcut.name}`;
          if (shortcut.aliases.length > 0) {
            help += ` (${shortcut.aliases.join(', ')})`;
          }
          help += `: ${shortcut.description}\n`;
        }
        help += '\n';
      }
    }

    help += '💡 Usage Examples:\n';
    help += '  core health          # Check system health\n';
    help += '  core scan 192.168.1.1 # Run network scan\n';
    help += '  core explain SQL injection # Explain concept\n';
    help += '  core learn           # Start learning mission\n';
    help += '  core logs            # Analyze security logs\n';
    help += '  core tools           # List available tools\n';
    help += '  core query malware   # Search knowledge base\n';
    help += '\n';
    help += '🎯 Natural Language:\n';
    help += '  Just type naturally: "Check system health", "Scan my network", etc.\n';

    return help;
  }

  /**
   * Get shortcut statistics
   */
  getStats(): any {
    const shortcuts = Array.from(this.shortcuts.values());
    const categories = new Map<string, number>();

    for (const shortcut of shortcuts) {
      categories.set(shortcut.category, (categories.get(shortcut.category) || 0) + 1);
    }

    return {
      total: shortcuts.length,
      byCategory: Object.fromEntries(categories),
      withAuth: shortcuts.filter(s => s.requiresAuth).length,
      withPermissions: shortcuts.filter(s => s.permissions).length,
      withNaturalLanguage: shortcuts.filter(s => s.naturalLanguage).length
    };
  }
}
