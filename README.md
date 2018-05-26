COMP90015 Distributed Systems Project 2
Team Daishu
Author: Zhengshang Liu, Weixin Zhao, Yucheng Yang, Wenhui Dong.

This project is created and compiled on eclipse IDE.
Using export runnable jar file function will be able to generate ActivityStreamerServer.jar and ActivityStreamerClient.jar.
These two jar files will run with following commands:
java -jar {path_to_folder}/ActivityStreamerServer.jar -rh [remote_host] -rp [remote_port] -lh [local_host] -lp [local_port] -s [secret]
java -jar {path_to_folder}/ActivityStreamerClient.jar -rh [remote_host] -rp [remote_port] -u [username] -s [secret]
The program has default value for [local_host] = "localhost", [local_port] = 3780, [remote_host] = null, [remote_port] = -1, [activity_interval] = 5000, [secret] = null, [username] = "anonymous". If any argument is not specified, default value will be used.

The Server application will generate a secret if not specified.
When running client without username and secret, the application will log in as anonymous; when running with only username, the application will generate a secret that will print to the console and use it to register and log in; when running with username and secret, the application will log in using provided information.