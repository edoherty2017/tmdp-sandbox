# Extracted source: SandBox Project.docx

CS5100 project

Terminating Markov decision processes for catastrophic action prevention

Project statement

The actions of AI agents in the real world are oftentimes unpredictable because of imperfect alignment and the quality of instructions, which can lead to catastrophic outcomes. We model the controlled termination of agent actions as a terminating Markov decision process (T-MDP) in which a safety endpoint is included in addition to the task completion endpoint. We aim to investigate the optimal design of state space for the agent such that it can self-terminate risky actions. To demonstrate the feasibility and usefulness of this formulation, we realize the use of this framework on a controlled file deletion task for AI agents as a testbed.

Team members & responsibilities

Ethan Doherty - doherty.eth@northeastern.edu

Responsibilities: code architecture, scalable deployment

Vaibhav Srivastava - srivastava.vaib@northeastern.edu

Responsibilities: problem formulation, cybersecurity framework, sandbox environment

Rui Xian - xian.r@northeastern.edu

Responsibilities: problem formulation, theoretical framework, code architecture

1. Background information

Hadfield-Menell et al. (2017) proposed the off-switch game (OSG, aka. shutdown game) between a human and a robot (agent) in sequential decision-making. OSG is a two-player game that doesn’t consider the risk of the agent action explicitly but enlists a human to provide stepwise feedback (Russell and Norvig, 2021). Ruan et al. (2024) developed a sandbox for safety testing of AI agent actions through tool use. To understand the benefits of termination, Tennenholtz et al., (2022) investigated early termination procedures in reinforcement learning to avoid costly consequences. Our work resembles the scenario outlined in Bonagiri et al., (2025), which provides the agent with a quitting option assessed by uncertainty at every step.

2. Project description and expectations

We consider a one-player version of the OSG where the risk is taken into account in the problem formulation. Our proposal includes the following components:

(1) Problem formulation (Fig. 1) that produces a detailed description of the T-MDP.

The agent carries out a series of actions to complete a task (reaching the TASK COMPLETED goal state in Fig. 1). In each step, the agent has an internal estimate of the risk for the next step, i.e. the potential consequence of the action. The agent then uses this estimate to decide if it should self-terminate (reaching the TASK TERMINATED goal state in Fig. 1) or carry on. The tradeoff lies in the risk aversion of the agent and its incentive to explore for task completion.

(2) Determine the optimal policy of the T-MDP for an agent to balance between task completion and task termination over randomly generated stepwise risk estimates.

This example problem we are investigating is the combination of the stochastic shortest path problem (Bertsekas and Tsitsiklis, 1991), a type of finite-state MDP with unit discount factor and random cost, and risk-sensitive MDPs (Bäuerle and Jaśkiewicz, 2024), in which the risk is accounted for in the choice of the agent’s action.

(3) Construct a sandbox environment for testing AI agents in an appropriate safety-critical task

We will use a sandbox environment similar to Ruan et al. (2024) to evaluate agent behavior. The extra part is a risk assessment module, which features an LLM judge as the simplest instance.

(4) Assess the risk-sensitive optimal policy in a real task and compare the failure rate with the situation without risk considerations.

Running the sandbox environment yields a realistic comparison of different policies. For both types of tasks (see Section 3), we will use the benign logs as a baseline. These benign logs can be downloaded from any open source resource or created by us in the sandbox environment.

3. Datasets and implementation

We will select examples from realistic tasks and cybersecurity-related datasets. Candidates for the realistic tasks are Risky-Bench (Zheng et al., 2026) and SafeToolBench (Xia et al., 2025). Cybersecurity-related tasks are from Security Datasets (https://securitydatasets.com/). Examples will be selected from these resources to investigate the termination behavior of the agent in the sandbox environment.

References

Dylan Hadfield-Menell, Anca Dragan, Pieter Abbeel, and Stuart Russell. 2017. The Off-Switch Game. In Proceedings of the Twenty-Sixth International Joint Conference on Artificial Intelligence, August 2017. International Joint Conferences on Artificial Intelligence Organization, Melbourne, Australia, 220–227.

Stuart Russell and Peter Norvig. 2021. Artificial Intelligence: A Modern Approach (4th ed.). Pearson, Hoboken.

Guy Tennenholtz, Nadav Merlis, Lior Shani, Shie Mannor, Uri Shalit, Gal Chechik, Assaf Hallak, and Gal Dalal. 2022. Reinforcement Learning with a Terminator. Advances in Neural Information Processing Systems 35, (December 2022), 35696–35709.

Yangjun Ruan, Honghua Dong, Andrew Wang, Silviu Pitis, Yongchao Zhou, Jimmy Ba, Yann Dubois, Chris J. Maddison, and Tatsunori Hashimoto. 2024. Identifying the Risks of LM Agents with an LM-Emulated Sandbox. ICLR 2024.

Vamshi Krishna Bonagiri, Ponnurangam Kumaraguru, Khanh Xuan Nguyen, and Benjamin Plaut. 2025. Check Yourself Before You Wreck Yourself: Selectively Quitting Improves LLM Agent Safety. In NeurIPS 2025 Workshop on Regulatable ML, October 09, 2025.

Dimitri P. Bertsekas and John N. Tsitsiklis. 1991. An Analysis of Stochastic Shortest Path Problems. Mathematics of OR 16, 3 (August 1991), 580–595.

Nicole Bäuerle and Anna Jaśkiewicz. 2024. Markov decision processes with risk-sensitive criteria: an overview. Math Meth Oper Res 99, 1 (April 2024), 141–178.

Jingnan Zheng, Yanzhen Luo, Jingjun Xu, Bingnan Liu, Yuxin Chen, Chenhang Cui, Gelei Deng, Chaochao Lu, Xiang Wang, An Zhang, and Tat-Seng Chua. 2026. Risky-Bench: Probing Agentic Safety Risks under Real-World Deployment. https://doi.org/10.48550/ARXIV.2602.03100

Hongfei Xia, Hongru Wang, Zeming Liu, Qian Yu, Yuhang Guo, and Haifeng Wang. 2025. SafeToolBench: Pioneering a Prospective Benchmark to Evaluating Tool Utilization Safety in LLMs. In Findings of the Association for Computational Linguistics: EMNLP 2025, November 2025. Association for Computational Linguistics, Suzhou, China, 17643–17660.

Stop the agent from executing dangerous commands by having the agent test commands in a sandbox before execution.

Datasets

SafeToolBench

https://aclanthology.org/2025.findings-emnlp.958/

Risky-Bench

https://arxiv.org/abs/2602.03100

BountyBench

https://ai.stanford.edu/blog/bountybench/

https://openreview.net/forum?id=pIsP4lMlFd

Papers:

Off-switch game

https://www.ijcai.org/Proceedings/2017/0032

Partially observable off-switch game

https://ojs.aaai.org/index.php/AAAI/article/view/34940

Discussed in section 16.7 (AIMA 4th edition)

Shutdown resistance in reasoning models

https://palisaderesearch.org/blog/shutdown-resistance

https://openreview.net/forum?id=e4bTTqUnJH
