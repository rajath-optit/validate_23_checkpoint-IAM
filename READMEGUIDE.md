### instructions for users to use your Python scripts `IAM_policy.py` and `security23checks.py`:


### pre-requisite
1.Create a Bash script:
```
Create a new file, let's call it setup_dependencies.sh, and open it in a text editor.
```
```
nano setup_dependencies.sh
```

Add the pip install commands:
Inside the script, add the pip install commands for all the dependencies you need.
```
#!/bin/bash

# Install psycopg2-binary
pip3 install psycopg2-binary

# If psycopg2-binary installation fails, try installing libpq-dev
if [ $? -ne 0 ]; then
    echo "Installation of psycopg2-binary failed. Installing libpq-dev..."
    sudo apt-get update
    sudo apt-get install -y libpq-dev
    echo "Attempting to install psycopg2 again..."
    pip3 install psycopg2
fi

# Install other dependencies
pip3 install boto3
pip3 install paramiko
pip3 install mysql-connector-python
pip3 install tabulate
```
3.Make the script executable:

After saving the script, make it executable by running:
```
chmod +x setup_dependencies.sh
```
Run the script:

Users can now run the script to install all the dependencies:
```
./setup_dependencies.sh
```


### For `IAM_policy.py`:

1. **Save or Clone the File**:
   - Save `IAM_policy.py` to your local machine or clone the repository:
     ```bash
     git clone https://github.com/yourusername/yourrepository.git
     ```

2. **Install Python 3**:
   - If you don't have Python 3 installed, download and install it from the official Python website: https://www.python.org/downloads/
   
3. **Navigate to the Directory**:
   - Open a terminal or command prompt and navigate to the directory where `IAM_policy.py` is saved or cloned.

4. **Run the Script**:
   - Use the following command to execute the script:
     ```bash
     python3 IAM_policy.py
     ```
   - This will analyze your AWS IAM policies and provide suggestions for improving security.


### For `security23checks.py`:

1. **Save or Clone the File**:
   - Save `security23checks.py` to your local machine or clone the repository:
     ```bash
     git clone https://github.com/yourusername/yourrepository.git
     ```

2. **Install Python 3**:
   - If you don't have Python 3 installed, download and install it from the official Python website: https://www.python.org/downloads/
   
3. **Navigate to the Directory**:
   - Open a terminal or command prompt and navigate to the directory where `security23checks.py` is saved or cloned.

4. **Run the Script**:
   - Use the following command to execute the script:
     ```bash
     python3 security23checks.py
     ```
   - This will perform 23 security checks and display the results in the terminal.



 **Review the Output**: Refer README(IAM).md file for iam security example output guide or README.md for security23checks.py output example.
                
        - After running the script, review the output in the terminal. It will display suggestions for enhancing the security of your AWS environment.


