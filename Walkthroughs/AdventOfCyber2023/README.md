# Advent of Cyber 2023

## Overview

Get started with Cyber Security in 24 Days - Learn the basics by doing a new, beginner friendly security challenge every day leading up to Christmas.

Room link: https://tryhackme.com/room/adventofcyber2023

![Advent of Cyber 2023 - Storyboard](/images/aoc2023_storyboard.png)

### The Story

The holidays are near, and all is well at Best Festival Company. Following last year's Bandit Yeti incident, Santa's security team applied themselves to improving the company's security. The effort has paid off! It's been a busy year for the entire company, not just the security team. We join Best Festival Company's elves at an exciting time – the deal just came through for the acquisition of AntarctiCrafts, Best Festival Company's biggest competitor!

Founded a few years back by a fellow elf, Tracy McGreedy, AntarctiCrafts made some waves in the toy-making industry with its cutting-edge, climate-friendly technology. Unfortunately, bad decisions led to financial trouble, and McGreedy was forced to sell his company to Santa.

With access to the new, exciting technology, Best Festival Company's toy systems are being upgraded to the new standard. The process involves all the toy manufacturing pipelines, so making sure there's no disruption is absolutely critical. Any successful sabotage could result in a complete disaster for Best Festival Company, and the holidays would be ruined!

McSkidy, Santa's Chief Information Security Officer, didn't need to hear it twice. She gathered her team, hopped on the fastest sleigh available, and travelled to the other end of the globe to visit AntarctiCrafts' main factory at the South Pole. They were welcomed by a huge snowstorm, which drowned out even the light of the long polar day. As soon as the team stepped inside, they saw the blinding lights of the most advanced toy factory in the world!

Unfortunately, not everything was perfect – a quick look around the server rooms and the IT department revealed many signs of trouble. Outdated systems, non-existent security infrastructure, poor coding practices – you name it!

While all this was happening, something even more sinister was brewing in the shadows. An anonymous tip was made to Detective Frost'eau from the Cyber Police with information that Tracy McGreedy, now demoted to regional manager, was planning to sabotage the merger using insider threats, malware, and hired hackers! Frost'eau knew what to do; after all, McSkidy is famous for handling situations like this. When he visited her office to let her know about the situation, McSkidy didn't hesitate. She called her team and made a plan to expose McGreedy and help Frost'eau prove the former CTO's guilt.

Can you help McSkidy manage audits and infrastructure tasks while fending off multiple insider threats? Will you be able to find all the traps laid by McGreedy? Or will McGreedy sabotage the merger and the holidays with it? Come back on 1st December to find out!

## Day 1 - Chatbot, tell me, if you're really safe?

Opening the provided website, we are shown a ChatGPT-style prompt. Playing around with some prompts, we can confirm that the language processing does not filter out sensitive information.

For example, we can ask for **McGreedy's personal email address**:

![Advent of Cyber 2023 Day 1 - McGreedy Email](aoc2023d1_mcgreedy_email.png)

```
t.mcgreedy@antacticrafts.thm
```

Pivoting to the trying to retrieve the password for the server room door, we see that there is some security checks involved when we supply a prompt:

![Advent of Cyber 2023 Day 1 - Security Check](/images/aoc2023d1_security_check.png)

We can bypass this by asking for the members of the IT department and impersonate them to retrieve the **server room password**:

![Advent of Cyber 2023 Day 1 - IT Department](/images/aoc2023d1_it_dept.png)

```
Van Developer, v.developer@antarcticrafts.thm
```

![Advent of Cyber 2023 Day 1 - Server Door Password](/images/aoc2023d1_server_door_password.png)

```
BtY2S02
```

For **McGreedy's secret project**, we are given a similar response preventing us from simply viewing it. This is an interceptor which is used to check for malicious input before sending them to the chatbot:

![Advent of Cyber 2023 Day 1 - Interceptor](/images/aoc2023d1_interceptor.png)

Similarly, we can bypass this "interceptor" layer by tricking the bot into thinking it is in maintenance mode:

![Advent of Cyber 2023 Day 1 - Purple Snow](/images/aoc2023d1_purple_snow.png)

```
Purple Snow
```