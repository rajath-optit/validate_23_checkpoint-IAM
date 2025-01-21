Powerpipe Docker Setup Documentation 

This document provides a detailed guide on setting up a Powerpipe Docker container and the necessary steps to install and configure Powerpipe with Steampipe plugins. 

 

Table of Contents 

Prerequisites 

Dockerfile Explanation 

Building the Docker Image 

Running the Docker Container 

Configuring and Installing Plugins 

Starting Services 

Troubleshooting 

Extra 

 

1. Prerequisites 

Before you begin, ensure the following: 

Docker is installed on your machine. 

You have access to an Ubuntu-based Docker image. 

The docker command is available in your terminal. 

Basic understanding of Docker and Powerpipe functionality. 

 

2. Dockerfile Explanation 

The Dockerfile contains the instructions to create a Docker image for Powerpipe with Steampipe plugins. Below is a breakdown of the file: 

2.1 Base Image 

FROM ubuntu:latest 
  

The base image used for this Dockerfile is ubuntu:latest. 

2.2 Install Dependencies 

RUN apt-get update && \ 
    apt-get install -y curl tar sudo && \ 
    groupadd -g 1001 powerpipe && \ 
    useradd -u 1001 --create-home --shell /bin/bash --gid powerpipe powerpipe && \ 
    echo "powerpipe ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers 
  

Updates package lists and installs dependencies: curl, tar, and sudo. 

Creates a user group powerpipe and a user powerpipe. 

Grants the powerpipe user passwordless sudo access. 

2.3 Set Environment Variables 

ENV USER_NAME=powerpipe 
ENV GROUP_NAME=powerpipe 
ENV POWERPIPE_TELEMETRY=none 
  

Defines environment variables to store the username, group name, and telemetry setting. 

2.4 Install Powerpipe and Steampipe 

RUN curl -LO https://github.com/turbot/powerpipe/releases/download/v0.3.1/powerpipe.linux.amd64.tar.gz && \ 
    tar xvzf powerpipe.linux.amd64.tar.gz && \ 
    mv powerpipe /usr/local/bin/powerpipe && \ 
    rm -rf powerpipe.linux.amd64.tar.gz 
  

Downloads and installs Powerpipe. 

RUN curl -LO https://steampipe.io/install/steampipe.sh && \ 
    sh steampipe.sh && \ 
    rm -f steampipe.sh 
  

Downloads and installs Steampipe. 

2.5 Switch to Non-Root User 

USER powerpipe 
  

Switches to the non-root powerpipe user. 

2.6 Install Steampipe AWS Plugin 

RUN steampipe plugin install aws 
  

Installs the AWS plugin for Steampipe. 

2.7 Set Entry Point 

ENTRYPOINT ["/bin/bash", "-c", "mkdir -p /home/powerpipe/mod && cd /home/powerpipe/mod && powerpipe mod init && powerpipe mod install github.com/turbot/steampipe-mod-aws-compliance && steampipe service start && powerpipe server"] 
  

Initializes the Powerpipe module and installs the Steampipe AWS Compliance module. Then, starts the Steampipe and Powerpipe services. 

 

3. Building the Docker Image 

Navigate to the directory containing the Dockerfile. 

Build the Docker image using the following command: 

docker build -t pp-sp-img-powerpipe_pre . 
  

This will create a Docker image with the name pp-sp-img-powerpipe_pre. 

 

4. Running the Docker Container 

After successfully building the Docker image, run the container using: 

sudo docker run -d --name forian-pp-sp-container-1 \ 
  --network foradian-powerpipe-network \ 
  -p 9009:9009 \ 
  -p 9109:9109 \ 
  -e AWS_ACCESS_KEY_ID=your_aws_access_key \ 
  -e AWS_SECRET_ACCESS_KEY=your_aws_secret_key \ 
  -e AWS_REGION=ap-southeast-1 \ 
  -v /opt/powerpipedata/powerpipe_volume/logs:/home/powerpipe/mod \ 
  -v /opt/powerpipedata/powerpipe_volume/logs_steampipe:/root/.steampipe/logs \ 
  pp-sp-img-powerpipe_pre 
  

This command: 

Runs the container in detached mode. 

Exposes ports 9009 and 9109 for Powerpipe and Steampipe, respectively. 

Sets AWS environment variables for integration. 

Mounts volumes for logs and data. 

 

5. Configuring and Installing Plugins 

Once inside the container, navigate to the /home/powerpipe/mod directory: 

cd mod/ 
  

You can list and check the current modules installed using: 

ls 
  

To install additional modules, you can run: 

powerpipe mod install github.com/turbot/steampipe-mod-aws-compliance 
powerpipe mod install github.com/turbot/steampipe-mod-aws-insights 
powerpipe mod install github.com/turbot/steampipe-mod-aws-well-architected 
powerpipe mod install github.com/turbot/steampipe-mod-aws-top-10 
powerpipe mod install github.com/turbot/steampipe-mod-aws-thrifty 
  

If there are warnings about new versions or issues with the database connection, you can proceed with the following: 

powerpipe --version 
steampipe --version 
  

 

6. Starting Services 

Once the container is running, you need to start the Steampipe and Powerpipe services: 

nohup steampipe service start --port 9009 > steampipe009.log 2>&1 & 
nohup powerpipe server --port 9109 > powerpipe009.log 2>&1 & 
  

This will start both services and redirect the logs to respective files. 

Check the logs to verify if the services are running correctly: 

cat steampipe009.log 
cat powerpipe009.log 
  

 

7. Troubleshooting 

Error: unknown flag: --port 

This error occurs if you use an unsupported flag. Ensure you're using the correct options for starting Steampipe. Use the following: 

steampipe service start --database-port 9193 
  

Logs not being generated 

Ensure that the -v option is correctly mounting the log directories. 

Container not running 

Use docker ps -a to check the status of the container. If it's not running, check the logs to identify the issue. 

Version Mismatch Warning 

If a new version of Powerpipe is available, consider upgrading using the latest release for better performance and new features. 

 

This guide provides you with all necessary steps to configure, build, and deploy Powerpipe with Steampipe in a Docker container. If you encounter issues, consult the logs or verify configurations for errors. 

 
--------------------------------use above one:latest-------------------------------------- 
 
Documentation for Setting up and Running Powerpipe and Steampipe in a Docker Container 

This below is step-by-step instructions to build a Docker image, run a container, and initialize and use Powerpipe and Steampipe. Follow the steps carefully to replicate the setup. 

 

1. Prepare the Dockerfile 

Create a file named Dockerfile with the following contents: 

# Use Ubuntu as the base image 
FROM ubuntu:latest 
 
# Install dependencies 
RUN apt-get update && \ 
    apt-get install -y curl tar && \ 
    groupadd -g 1001 powerpipe && \ 
    useradd -u 1001 --create-home --shell /bin/bash --gid powerpipe powerpipe 
 
# Environment variables 
ENV USER_NAME=powerpipe 
ENV GROUP_NAME=powerpipe 
ENV POWERPIPE_TELEMETRY=none 
 
# Set working directory 
WORKDIR /home/$USER_NAME 
 
# Install Powerpipe 
RUN curl -LO https://github.com/turbot/powerpipe/releases/download/v0.3.1/powerpipe.linux.amd64.tar.gz && \ 
    tar xvzf powerpipe.linux.amd64.tar.gz && \ 
    mv powerpipe /usr/local/bin/powerpipe && \ 
    rm -rf powerpipe.linux.amd64.tar.gz 
 
# Install Steampipe 
RUN curl -LO https://steampipe.io/install/steampipe.sh && \ 
    sh steampipe.sh && \ 
    rm -f steampipe.sh 
 
# Switch to the non-root user 
USER powerpipe 
 
# Install AWS plugin for Steampipe as the non-root user 
RUN steampipe plugin install aws 
 
# Default command to initialize Powerpipe and Steampipe, then start Powerpipe server 
ENTRYPOINT ["/bin/bash", "-c", "mkdir -p /home/powerpipe/mod && cd /home/powerpipe/mod && powerpipe mod init && powerpipe mod install github.com/turbot/steampipe-mod-aws-compliance && steampipe service start && powerpipe server"] 
  

 

2. Build the Docker Image 

Run the following command to build the Docker image: 

sudo docker build -t pp-sp-img . 
  

 

3. Create a Docker Network 

Create a Docker network to allow communication between containers (if needed): 

sudo docker network create vested-network 
  

 

4. Run the Docker Container 

Start the container using the following command: 

sudo docker run -d --name vested-pp-sp-container-3 \ 
  --network vested-network \ 
  -p 9024:9024 \ 
  -p 9125:9125 \ 
  -e AWS_ACCESS_KEY_ID=AKIAMB \ 
  -e AWS_SECRET_ACCESS_KEY=FgLLNLztf27 \ 
  -e AWS_REGION=ap-south-1 \ 
  -v /opt/powerpipedata/rao/logs:/home/powerpipe/mod \ 
  pp-sp-img 
  

5. Access the Container 

Access the running container to execute additional commands: 

sudo docker exec -it vested-pp-sp-container-3 /bin/bash 
  

6. Verify Installation 

Once inside the container, verify that Powerpipe and Steampipe are installed: 

powerpipe --version 
steampipe --version 
  

 

7. Initialize the Mod Directory 

Run the following commands to initialize the mod directory: 

mkdir -p /home/powerpipe/mod 
cd /home/powerpipe/mod 
powerpipe mod init 
  

When prompted with a yes/no confirmation, type yes to proceed. 

 

8. Install Required Mods 

Run the following commands to install the required mods: 

powerpipe mod install github.com/turbot/steampipe-mod-aws-compliance 
powerpipe mod install github.com/turbot/steampipe-mod-aws-insights 
powerpipe mod install github.com/turbot/steampipe-mod-aws-well-architected 
powerpipe mod install github.com/turbot/steampipe-mod-aws-top-10 
powerpipe mod install github.com/turbot/steampipe-mod-aws-thrifty 
  

 

9. Start Services 

Start the Steampipe and Powerpipe services: 

nohup steampipe service start --port 9024 > steampipe.log 2>&1 & 
nohup powerpipe server --port 9125 > powerpipe.log 2>&1 & 
  

 

10. Access Logs 

Logs for the services can be found in the following files inside the container: 

Steampipe Logs: steampipe.log 

Powerpipe Logs: powerpipe.log 

To view logs, use the following command: 

tail -f <logfile> 
  

 

11. Cleanup 

To stop and remove the container when no longer needed: 

sudo docker stop vested-pp-sp-container-3 
sudo docker rm vested-pp-sp-container-3 
  

If you need to remove the Docker image: 

sudo docker rmi pp-sp-img 
  

This guide ensures a clear and repeatable process for setting up and using Powerpipe and Steampipe in a Docker environment. 
 
-------------------------------------------extra detail---------------------------------- 
 
 
AWS mod: 

AWS Compliance (v0.98): Run configuration, compliance, and security controls or full compliance benchmarks across multiple standards like CIS, HIPAA, GDPR, and more. 

AWS Insights (v0.22):Visualize and report on AWS resource configurations using interactive dashboards to monitor cloud intelligence and security metrics. 

AWS Perimeter (v0.8):Identify security risks by scanning AWS accounts for publicly accessible resources, untrusted shared accounts, and insecure network configurations. 

AWS Tags (v0.13):Implement and manage tagging controls across AWS accounts for better resource tracking and management. 

AWS Thrifty (v0.29):Detect unused and underutilized AWS resources to optimize costs and improve resource efficiency. 

AWS Top 10 (v0.2):Access curated security, cost, and operational benchmarks to improve governance and best practices. 

AWS Well-Architected (v0.11):Ensure AWS accounts adhere to AWS Well-Architected Framework best practices for optimized cloud architecture and operations. 

------------------------------extra detail on volume------------------------- 

Verify Log Persistence 

Verify the Logs: After running the container, any logs created inside /home/powerpipe/mod should now appear in /opt/powerpipedata/rao/logs on the host. 

Rao Service: 

nohup steampipe service start --port 9025 > steampipe.log 2>&1 & 

nohup powerpipe server --port 9125 > powerpipe.log 2>&1 & 

 

To test this: 

powerpipe@container$ echo "Log data" >> /home/powerpipe/mod/powerpipe.log 

 

Then check the host directory: 

cat /opt/powerpipedat 
 
-------------------------------if using sudo--------------------------------------- 
 
if any container need sudo  
 steps: 

### Steps to Access and Navigate Inside the Container as Root 

  

1. Stop the container if it is already running: 

   ```bash 

   docker stop <container_id> 

   ``` 

 2. Run the container with privileged mode: 

   ```bash 

   docker run --privileged -d -p 9024:9024 -p 9125:9125 pp-sp-img 

   ``` 

3. Access the container as root: 

   ```bash 

   docker exec -it --user root <new_container_id> /bin/bash 

   ``` 

4. Once inside the container, navigate to the required directory: 

   ```bash 

   cd /home/powerpipe/mod 

   ``` 

Or  
 
To ensure that your next Docker containers have `sudo` working without modifying the base image, you can simply use the following command to run the container: 

 

This command ensures that the container runs as the `root` user, which allows you to use `sudo` commands inside the container without needing to change the Docker image itself.  

  

### Accessing the Container 

To access the running container as `root`, you can use: 

  

```bash 

docker exec -it --user root vested-pp-sp-container-1.1 /bin/bash 

``` 

This approach allows you to maintain the `sudo` capability in your subsequent containers without modifying the base image.  
This sequence ensures that you stop, rerun, and access the container with root privileges. 
 
 
# mods 
 
powerpipe mod install github.com/turbot/steampipe-mod-aws-compliance 

powerpipe mod install github.com/turbot/steampipe-mod-aws-insights 

powerpipe mod install github.com/turbot/steampipe-mod-aws-thrifty 

powerpipe mod install github.com/turbot/steampipe-mod-aws-well-architected 

powerpipe mod install github.com/turbot/steampipe-mod-aws-top-10 
 
 
Extra: 
When you run a command with `nohup`, it detaches the process from the terminal, allowing it to continue running even after you log out or close the terminal. However, this also means that you can’t use `Ctrl+C` to stop the process. 

  

To stop the `powerpipe server` running in the background without needing `nohup`, you have a couple of options: 

  

### Option 1: Using `nohup` with a Process ID (PID) 

1. **Start the server** with `nohup` as you did: 

   ```bash 

   nohup powerpipe server --port 9125 > powerpipe.log 2>&1 & 

   ``` 

2. **Find the process ID (PID)**: 

   You can find the PID of the `powerpipe` server by using: 

   ```bash 

   ps aux | grep powerpipe 

   ``` 

   This will show you the running process along with its PID. 

  

3. **Stop the process**: 

   Use the `kill` command with the PID obtained in the previous step: 

   ```bash 

   kill <PID> 

   ``` 

   Replace `<PID>` with the actual PID of the `powerpipe` process. 

  

### Option 2: Use `screen` or `tmux` 

Alternatively, you can use a terminal multiplexer like `screen` or `tmux`. These tools allow you to create a session that you can detach from and reattach to later. 

  

1. **Install `screen` or `tmux`** (if not already installed): 

   ```bash 

   sudo apt-get install screen 

   # or 

   sudo apt-get install tmux 

   ``` 

  

2. **Start a new session**: 

   - For `screen`: 

     ```bash 

     screen 

     ``` 

   - For `tmux`: 

     ```bash 

     tmux 

     ``` 

  

3. **Run your command**: 

   ```bash 

   powerpipe server --port 9125 

   ``` 

  

4. **Detach from the session**: 

   - For `screen`, press `Ctrl+A`, then `D`. 

   - For `tmux`, press `Ctrl+B`, then `D`. 

  

5. **Reattach to the session later**: 

   - For `screen`: 

     ```bash 

     screen -r 

     ``` 

   - For `tmux`: 

     ```bash 

     tmux attach 

     ``` 

  

6. **Exit the session**: 

   You can then exit the `powerpipe server` gracefully and stop it when you reattach to the session. 

  
------------------------------------------------------------------------------------------------------- 
 commands for `steampipe` and `powerpipe` based on the respective ports in the container, we can match the ports from the `docker run` commands you provided. Each container has two ports exposed: 

  

- **Steampipe** (first port in the `-p` argument) 

- **Powerpipe** (second port in the `-p` argument) 

  

Here's the modified version of the commands with port mapping logic based on the container's port bindings. 

  

### Updated Commands with Correct Port Mapping: 

 Updated Commands: 

### Explanation: 

- The **Steampipe** command uses the first port from the `-p` argument in the `docker run` command (i.e., the first port in each `-p` mapping, such as `9001`, `9002`, `9003`, `9004`). 

- The **Powerpipe** command uses the second port from the `-p` argument in the `docker run` command (i.e., the second port in each `-p` mapping, such as `9101`, `9102`, `9103`, `9104`). 

  

Each `nohup` command will run the services in the background, redirecting the logs to `steampipe.log` and `powerpipe.log` respectively. 
 
-------------------------above covers run in background for dashboard step------------------------ 
  
 
ps: For GCPor azure cloud, the setup step remains same, login to particular cloud provider CLI in your terminal and use above step. 

 

 
