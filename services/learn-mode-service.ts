import { EventBus } from '../events/event-bus';
import { LLMClient } from '../types';
import { Logger } from '../utils/logger';

export interface TrainingMission {
  id: string;
  title: string;
  description: string;
  difficulty: 'beginner' | 'intermediate' | 'advanced';
  category: 'red-team' | 'blue-team' | 'general';
  objectives: string[];
  hints: string[];
  solution: string;
  estimatedTime: number; // in minutes
  prerequisites: string[];
  tools: string[];
  simulationData?: any;
}

export interface UserProgress {
  userId: string;
  completedMissions: string[];
  currentMission?: string;
  score: number;
  achievements: string[];
  learningPath: string;
  lastActivity: Date;
}

export interface LearnModeOptions {
  interactive: boolean;
  provideFeedback: boolean;
  enableHints: boolean;
  simulationMode: boolean;
  difficulty: 'beginner' | 'intermediate' | 'advanced';
}

export class LearnModeService {
  private readonly client: LLMClient;
  private readonly logger: Logger;
  private readonly eventBus: EventBus;
import * as fs from 'fs-extra'; // For persistence
import * as path from 'path';   // For persistence

export interface TrainingMission {
  id: string;
// ... (rest of TrainingMission interface) ...
// (Ensure all interface definitions are at the top or imported)
// For brevity, assuming interfaces are defined above or imported.

export class LearnModeService {
  private readonly client: LLMClient;
  private readonly logger: Logger;
  private readonly eventBus: EventBus;
  private readonly missions: Map<string, TrainingMission> = new Map();
  private userProgress: Map<string, UserProgress> = new Map(); // Made mutable for loading
  private readonly userProgressFilePath: string;

  constructor(client: LLMClient, logger: Logger, eventBus: EventBus, dataPath: string = './data/learning') {
    this.client = client;
    this.logger = logger;
    this.eventBus = eventBus;
    this.userProgressFilePath = path.join(dataPath, 'user_progress.json');
    fs.ensureDirSync(dataPath); // Ensure data directory exists

    this.initializeMissions();
    this.loadUserProgress(); // Load progress on startup
  }

  private async loadUserProgress(): Promise<void> {
    try {
      if (await fs.pathExists(this.userProgressFilePath)) {
        const fileContent = await fs.readFile(this.userProgressFilePath, 'utf-8');
        const progressData = JSON.parse(fileContent) as Array<[string, UserProgress]>;
        this.userProgress = new Map(progressData.map(([userId, data]) => [
            userId,
            { ...data, lastActivity: new Date(data.lastActivity) } // Ensure date is properly parsed
        ]));
        this.logger.info(`User progress loaded from ${this.userProgressFilePath}`);
      } else {
        this.logger.info('No user progress file found. Starting with empty progress data.');
      }
    } catch (error: any) {
      this.logger.error(`Failed to load user progress: ${error.message}`, error);
      this.userProgress = new Map(); // Start fresh on error
    }
  }

  private async saveUserProgress(): Promise<void> {
    try {
      const progressData = Array.from(this.userProgress.entries());
      await fs.writeFile(this.userProgressFilePath, JSON.stringify(progressData, null, 2));
      this.logger.info(`User progress saved to ${this.userProgressFilePath}`);
    } catch (error: any) {
      this.logger.error(`Failed to save user progress: ${error.message}`, error);
    }
  }

  private initializeMissions(): void {
    // Initialize built-in training missions
    const missions: TrainingMission[] = [
      {
        id: 'reconnaissance-basics',
        title: 'Reconnaissance Fundamentals',
        description: 'Learn the basics of information gathering and reconnaissance techniques.',
        difficulty: 'beginner',
        category: 'red-team',
        objectives: [
          'Understand passive reconnaissance techniques',
          'Learn about OSINT gathering',
          'Practice network enumeration',
          'Identify target services and versions'
        ],
        hints: [
          'Start with passive techniques to avoid detection',
          'OSINT tools can provide valuable information without direct contact',
          'Port scanning should be done carefully to avoid triggering alarms'
        ],
        solution: 'Complete reconnaissance involves both passive and active techniques, starting with OSINT and progressing to careful active enumeration.',
        estimatedTime: 45,
        prerequisites: [],
        tools: ['nmap', 'osquery', 'whois'],
        simulationData: {
          targetNetwork: '192.168.1.0/24',
          openPorts: [22, 80, 443, 3389],
          services: ['SSH', 'HTTP', 'HTTPS', 'RDP']
        }
      },
      {
        id: 'network-monitoring',
        title: 'Network Monitoring and Analysis',
        description: 'Learn to monitor network traffic and detect suspicious activities.',
        difficulty: 'intermediate',
        category: 'blue-team',
        objectives: [
          'Set up network monitoring',
          'Analyze traffic patterns',
          'Detect anomalies',
          'Create detection rules'
        ],
        hints: [
          'Baseline normal traffic patterns first',
          'Look for unusual connection patterns',
          'Monitor for known attack signatures'
        ],
        solution: 'Effective network monitoring requires understanding normal patterns and using both signature-based and anomaly-based detection.',
        estimatedTime: 60,
        prerequisites: ['networking-fundamentals'],
        tools: ['snort', 'wireshark', 'osquery'],
        simulationData: {
          normalTraffic: 'baseline_traffic.pcap',
          maliciousTraffic: 'attack_traffic.pcap'
        }
      },
      {
        id: 'log-analysis',
        title: 'Security Log Analysis',
        description: 'Master the art of analyzing security logs to identify threats.',
        difficulty: 'intermediate',
        category: 'blue-team',
        objectives: [
          'Understand different log types',
          'Learn log correlation techniques',
          'Identify attack patterns in logs',
          'Create effective queries'
        ],
        hints: [
          'Time correlation is crucial for understanding attack sequences',
          'Look for patterns across multiple log sources',
          'Failed login attempts often indicate brute force attacks'
        ],
        solution: 'Log analysis requires understanding the context of different log types and correlating events across multiple sources.',
        estimatedTime: 75,
        prerequisites: ['system-administration'],
        tools: ['grep', 'awk', 'splunk', 'elastic'],
        simulationData: {
          sampleLogs: 'security_logs.txt',
          attackPatterns: ['brute_force', 'sql_injection', 'xss']
        }
      }
    ];

    missions.forEach(mission => {
      this.missions.set(mission.id, mission);
    });

    this.logger.info(`Initialized ${missions.length} training missions`);
  }

  public async startMission(userId: string, missionId: string, options: LearnModeOptions): Promise<string> {
    const mission = this.missions.get(missionId);
    if (!mission) {
      throw new Error(`Mission ${missionId} not found`);
    }

    const userProgress = this.getUserProgress(userId);

    // Check prerequisites
    if (mission.prerequisites.length > 0) {
      const missingPrereqs = mission.prerequisites.filter(prereq =>
        !userProgress.completedMissions.includes(prereq)
      );
      if (missingPrereqs.length > 0) {
        throw new Error(`Missing prerequisites: ${missingPrereqs.join(', ')}`);
      }
    }

    userProgress.currentMission = missionId;
    userProgress.lastActivity = new Date();
    this.userProgress.set(userId, userProgress);
    await this.saveUserProgress(); // Save progress

    this.eventBus.emit('learn-mode.mission.started', {
      userId,
      missionId,
      mission,
      options
    });

    let response = `🎯 **Mission Started: ${mission.title}**\n\n`;
    response += `📋 **Description:** ${mission.description}\n\n`;
    response += `⏱️ **Estimated Time:** ${mission.estimatedTime} minutes\n`;
    response += `🔧 **Tools:** ${mission.tools.join(', ')}\n\n`;
    response += `📝 **Objectives:**\n`;
    mission.objectives.forEach((objective, index) => {
      response += `${index + 1}. ${objective}\n`;
    });

    if (options.enableHints) {
      response += `\n💡 **Hints Available:** Use 'hint' command to get guidance\n`;
    }

    if (options.simulationMode) {
      response += `\n🔒 **Simulation Mode:** All actions will be simulated safely\n`;
    }

    response += `\n🚀 **Ready to begin? Type 'proceed' to start the mission!**`;

    return response;
  }

  public async provideFeedback(userId: string, action: string, result: any): Promise<string> {
    const userProgress = this.getUserProgress(userId);
    if (!userProgress.currentMission) {
      return "No active mission. Start a mission first with 'start-mission <mission-id>'.";
    }

    const mission = this.missions.get(userProgress.currentMission);
    if (!mission) {
      return "Current mission not found.";
    }

    // Use LLM to provide contextual feedback
    const prompt = `
    You are an expert cybersecurity instructor providing feedback on a student's action.

    Mission: ${mission.title}
    Mission Description: ${mission.description}
    Student Action: ${action}
    Result: ${JSON.stringify(result)}

    Provide constructive feedback that:
    1. Explains what the student did well
    2. Identifies areas for improvement
    3. Suggests next steps
    4. Provides educational context
    5. Maintains an encouraging tone

    Keep the response concise but informative.
    `;

    try {
      const feedback = await this.client.generate({ prompt });

      this.eventBus.emit('learn-mode.feedback.provided', {
        userId,
        missionId: userProgress.currentMission,
        action,
        result,
        feedback
      });

      return `📚 **Instructor Feedback:**\n\n${feedback}`;
    } catch (error) {
      this.logger.error('Error generating feedback:', error);
      return "Unable to generate feedback at this time. Please try again later.";
    }
  }

  public async provideHint(userId: string, context?: string): Promise<string> {
    const userProgress = this.getUserProgress(userId);
    if (!userProgress.currentMission) {
      return "No active mission. Start a mission first with 'start-mission <mission-id>'.";
    }

    const mission = this.missions.get(userProgress.currentMission);
    if (!mission) {
      return "Current mission not found.";
    }

    // Select appropriate hint based on context or progress
    let hint = '';
    if (mission.hints.length > 0) {
      // For now, return a random hint, but this could be made more intelligent
      const randomHint = mission.hints[Math.floor(Math.random() * mission.hints.length)];
      hint = randomHint;
    }

    if (context) {
      // Use LLM to provide contextual hint
      const prompt = `
      You are a cybersecurity instructor providing a hint for a student.

      Mission: ${mission.title}
      Mission Description: ${mission.description}
      Student Context: ${context}
      Available Hints: ${mission.hints.join('; ')}

      Provide a helpful hint that guides the student without giving away the complete solution.
      Make it educational and encourage learning.
      `;

      try {
        hint = await this.client.generate({ prompt });
      } catch (error) {
        this.logger.error('Error generating contextual hint:', error);
        // Fallback to predefined hint
      }
    }

    this.eventBus.emit('learn-mode.hint.provided', {
      userId,
      missionId: userProgress.currentMission,
      context,
      hint
    });

    return `💡 **Hint:** ${hint}`;
  }

  public async completeMission(userId: string, submissionData: any): Promise<string> {
    const userProgress = this.getUserProgress(userId);
    if (!userProgress.currentMission) {
      return "No active mission to complete.";
    }

    const mission = this.missions.get(userProgress.currentMission);
    if (!mission) {
      return "Current mission not found.";
    }

    // Evaluate submission using LLM
    const prompt = `
    You are evaluating a student's completion of a cybersecurity training mission.

    Mission: ${mission.title}
    Objectives: ${mission.objectives.join('; ')}
    Student Submission: ${JSON.stringify(submissionData)}
    Expected Solution: ${mission.solution}

    Evaluate the submission and provide:
    1. A score out of 100
    2. Whether the mission is complete (true/false)
    3. Detailed feedback on what was done well
    4. Areas for improvement
    5. Next recommended steps

    Return as JSON: {"score": number, "complete": boolean, "feedback": string, "improvements": string[], "nextSteps": string[]}
    `;

    try {
      const evaluationResponse = await this.client.generate({ prompt });
      const evaluation = JSON.parse(evaluationResponse);

      if (evaluation.complete) {
        // Mark mission as completed
        if (!userProgress.completedMissions.includes(userProgress.currentMission)) {
          userProgress.completedMissions.push(userProgress.currentMission);
        }
        userProgress.score += evaluation.score;
        userProgress.currentMission = undefined;
        userProgress.lastActivity = new Date();
        this.userProgress.set(userId, userProgress);
         await this.saveUserProgress(); // Save progress

        this.eventBus.emit('learn-mode.mission.completed', {
          userId,
          missionId: mission.id,
          score: evaluation.score,
          evaluation
        });

        let response = `🎉 **Mission Completed: ${mission.title}**\n\n`;
        response += `📊 **Score:** ${evaluation.score}/100\n\n`;
        response += `📚 **Feedback:** ${evaluation.feedback}\n\n`;

        if (evaluation.nextSteps && evaluation.nextSteps.length > 0) {
          response += `🔜 **Next Steps:**\n`;
          evaluation.nextSteps.forEach((step: string, index: number) => {
            response += `${index + 1}. ${step}\n`;
          });
        }

        return response;
      } else {
        let response = `📋 **Mission In Progress**\n\n`;
        response += `📊 **Current Score:** ${evaluation.score}/100\n\n`;
        response += `📚 **Feedback:** ${evaluation.feedback}\n\n`;

        if (evaluation.improvements && evaluation.improvements.length > 0) {
          response += `🔧 **Areas for Improvement:**\n`;
          evaluation.improvements.forEach((improvement: string, index: number) => {
            response += `${index + 1}. ${improvement}\n`;
          });
        }

        return response;
      }
    } catch (error) {
      this.logger.error('Error evaluating mission submission:', error);
      return "Unable to evaluate submission at this time. Please try again later.";
    }
  }

  public listMissions(difficulty?: string, category?: string): string {
    const missions = Array.from(this.missions.values());
    const filteredMissions = missions.filter(mission => {
      if (difficulty && mission.difficulty !== difficulty) return false;
      if (category && mission.category !== category) return false;
      return true;
    });

    if (filteredMissions.length === 0) {
      return "No missions found matching your criteria.";
    }

    let response = "📚 **Available Training Missions:**\n\n";
    filteredMissions.forEach(mission => {
      response += `**${mission.id}** - ${mission.title}\n`;
      response += `  📊 Difficulty: ${mission.difficulty}\n`;
      response += `  🎯 Category: ${mission.category}\n`;
      response += `  ⏱️ Time: ${mission.estimatedTime} minutes\n`;
      response += `  📝 ${mission.description}\n\n`;
    });

    return response;
  }

  public getProgress(userId: string): string {
    const progress = this.getUserProgress(userId);

    let response = `📊 **Your Learning Progress:**\n\n`;
    response += `🎯 **Completed Missions:** ${progress.completedMissions.length}\n`;
    response += `📈 **Total Score:** ${progress.score}\n`;
    response += `🏆 **Achievements:** ${progress.achievements.length}\n`;
    response += `📚 **Learning Path:** ${progress.learningPath}\n\n`;

    if (progress.currentMission) {
      const mission = this.missions.get(progress.currentMission);
      response += `🔄 **Current Mission:** ${mission?.title ?? 'Unknown'}\n`;
    }

    if (progress.completedMissions.length > 0) {
      response += `✅ **Completed Missions:**\n`;
      progress.completedMissions.forEach(missionId => {
        const mission = this.missions.get(missionId);
        response += `  - ${mission?.title ?? missionId}\n`;
      });
    }

    return response;
  }

  private getUserProgress(userId: string): UserProgress {
    if (!this.userProgress.has(userId)) {
      this.userProgress.set(userId, {
        userId,
        completedMissions: [],
        score: 0,
        achievements: [],
        learningPath: 'beginner',
        lastActivity: new Date()
      });
      // Note: Persistence is handled by calling methods like startMission/completeMission
      // after they have potentially created/modified userProgress.
    }
    return this.userProgress.get(userId)!;
  }

  public async explainConcept(concept: string): Promise<string> {
    const prompt = `
    You are an expert cybersecurity instructor. Explain the following concept in a clear, educational way:

    Concept: ${concept}

    Provide:
    1. A clear definition
    2. Why it's important in cybersecurity
    3. Common use cases or scenarios
    4. Examples or analogies to help understanding
    5. Related concepts to explore

    Keep the explanation accessible but comprehensive.
    `;

    try {
      const explanation = await this.client.generate({ prompt });
      return `📚 **Concept Explanation: ${concept}**\n\n${explanation}`;
    } catch (error) {
      this.logger.error('Error explaining concept:', error);
      return "Unable to explain concept at this time. Please try again later.";
    }
  }
}
