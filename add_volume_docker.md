persistance volume test successfully tested. above is the screen shot.

 ![741efafe-c200-4ab9-9753-178537c49ac1](https://github.com/user-attachments/assets/72e57294-13d6-4ad0-b8a4-061dbd025aa1)

container
![f141f835-4957-4177-a6fd-0ea9e67922c7](https://github.com/user-attachments/assets/86a736da-8fc7-4707-8d0d-4456cc66f0e7)

 
host machine
 ![983bd382-9b95-40c8-a55c-17a5f0cf1be2](https://github.com/user-attachments/assets/c9a214af-e636-46ed-b681-d558df4f0de5)

To add persistant volume we have to stop and delete running report and attach volume. 
 
Check data peristence on container


- Test by attaching a data volume to the container and check for persistence of data
 
 
 
 
/opt/powerpipedata/{customer}


==========================================='''''==========================
use below step "stop and remove running container and then restart by adding -v tag like given below."



sudo mkdir -p /opt/powerpipedata/capitalmind


ls /opt/powerpipedata/capitalmind
 
 
sudo docker run -d --name myaccontainer1 \
  --network aws_account1_network \
  -p 9194:9194 \
  -p 9040:9040 \
  -e AWS_ACCESS_KEY_ID= \
  -e AWS_SECRET_ACCESS_KEY= \
  -e AWS_REGION=us-east-1 \
  -v /opt/powerpipedata/capitalmind:/opt/powerpipedata/capitalmind \
  pp-sp-img
 
 
docker exec -it myaccontainer1 /bin/bash
 
#Check Data Persistence:
 
#Enter the container:
 
docker exec -it myaccontainer1 /bin/bash


Write some data inside /opt/powerpipedata/capitalmind within the container:
 
echo "Test data for persistence" > /opt/powerpipedata/capitalmind/testfile.txt
 
#Restart the Container:
 
#Stop the container:
 
docker stop myaccontainer1


Start the container again:
 
docker start myaccontainer1
 
#Verify Data Persistence:
 
#Re-enter the container:
 
docker exec -it myaccontainer1 /bin/bash


Check if the data is still there:
 
cat /opt/powerpipedata/capitalmind/testfile.txt



 
