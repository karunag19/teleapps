Deploy the app to borg environment:
    In Cli:
        Command: 
            aws s3 ls
                It will list folders in the default profile (demo profile)
            export AWS_PROFILE=borg
            aws s3 ls
                Verify the aws cli is point to borg environment.

    Change samconfig.toml
        Rename "samconfig.toml" to "samconfig_demo.toml"   
        Rename "samconfig_bord.toml" to "samconfig.toml"
    Run deploy command:
        sam deploy --template-file template_cognito.yaml -g
    Note:
        Since borg environment has more email, you have to manually increase the memory size of lambda(borg_GenesysQueue)
        from 512 to 2048
    Angular App deploy:
        update the config.json file in assets/config.json
            {
                "client_id": "70ipojcad395u5kub2hfcrafqt",
                "cloud_url": "https://ov0p56rgmd.execute-api.ap-southeast-2.amazonaws.com/Testing",
                "auth_url": "https://borg-674882051971.auth.ap-southeast-2.amazoncognito.com/login?response_type=token&client_id={{client-id}}&redirect_uri={{redirect-uri}}"
            }
        copy the latest angular app
            aws s3 cp ./ s3://scheduler.borg.com.au/ --recursive
        Login:
            URL: https://d1n9tc1slbls7k.cloudfront.net/
            User Name: karunag19@gmail.com
            Password: T3l3appsgc#  


AWS SAM -> AWS Serverless Application Model
We can write lambda application localy
We can test the lambda application using "sam local"
Using SAM command we can package the lambda application using "sam package"
We can also deploy the application using "sam deploy"
To RUN the SAM CLI, we required the following prerequest:
    - aws cli -> with user profile configured
    - docker
    - sam cli

Run the below command to create packages.

To create package using sam cli:
    sam init --runtime python3.7 --name <application name>

Once the default app files created, you can create folder for your lambda application
    Inside the filder create a .py file for lambda function.

Configure the template.yaml file with the lambda configuration

To run the sam localy
    sam local invoke HelloWorldFunction --no-event
    sam local invoke HelloWorldFunction --event <json event filename>
    e.g
    sam local invoke GenesysFunction --event json/scheduled_event.json
    Note: the above code will simulate event trigger from event bus - Schedule event.

To start the local web interface
    sam local start-api
    sam local start-api --host 10.10.42.26 --port 3000
    Note: if you want to configure the borg environment to access, before running
        you have to set the aws to borg environment -> export AWS_PROFILE=borg
        change the template.yaml to borg environment and run the above command.
    Note: To run local dont use template_cognito.yaml, use only default template.  In template we had set the 
        environment variable to demo environment.
    E.g. (Dont use the below command in local)
        sam local start-api --host 10.10.42.26 --port 3000 --template-file template_cognito.yaml

To View Log:
    Go to :CloudWatch
        Inside -> select "Log groups" & select /aws/lambda/Genesys


To check using curl:
    curl http://10.10.42.26:3000/hello
    Note: you need to specify the method (getec2region), if not specify it through an error "Missing Authentication Token"

To create packages:
    sam package --template-file <template file name> --output-template-file <output file name> --s3-bucket <s3 bucket name>
    sam package --template-file template.yaml --output-template-file deploy.yaml --s3-bucket deployment-teleapps-schedule
    sam package --template-file template_temp.yaml --output-template-file deploy_temp.yaml --s3-bucket deployment-teleapps-temp

To deploy packages:
    sam deploy --template-file deploy.yaml --stack-name MySAMLambdaStack --capabilities CAPABILITY_IAM
    sam deploy --template-file deploy.yaml --stack-name TeleApps-Schedule --capabilities CAPABILITY_IAM
    sam deploy --template-file deploy_temp.yaml --stack-name TeleApps-Temp --capabilities CAPABILITY_IAM
    Guided deployment:
        sam deploy --template-file template_cognito.yaml -g
            Note: Once Parameters are stored in "samconfig.toml" you can run without -g
            sam deploy --template-file template_cognito.yaml 


Multiple AWS Account:
    AWS_PROFILE=default sam package # with params
    AWS_PROFILE=live sam deploy # with params

Reference:
    https://github.com/awslabs/serverless-application-model/blob/master/versions/2016-10-31.md#awsserverlessfunction
    
Install Packages as Layer:
    cd dependencies/python/lib/python3.8/site-packages/
    pip install <package name> -t .
    e.g
    pip install jsonschema -t .
    pip install python-dateutil -t .

Role:
    If you got error "provided role cannot be assumed by principal" when you create corn job, in IAM role you have to 
    add  "events.amazonaws.com" in "Trusted Relationships"

To Enable "Time Based One Time Password"
    From access token get "SecretCode" using "associate_software_token" api method.
    Once you got the secret token: -> use google authenticator and pass the secrete key, it will start generate code.
    Call "verify_software_token" method and pass the google authenticator code.
    It would return "SUCCESS"
    
AWS CLI:
    aws s3 ls
    Create profile using:
        .aws/config
    List user by profile
        aws iam list-users --profile default
        Note: default is the profile name
    List s3 by profile
        aws s3 ls
        aws s3 ls --profile <profile name>
        aws s3 ls --profile cust1
    Change Profile:
        export AWS_PROFILE=<profile_name>
        export AWS_PROFILE=cust1
        export AWS_PROFILE=borg
    Copy:
        aws s3 cp s3://gc-teleapps.net/ ./ --recursive
        aws s3 cp ./ s3://gc-teleapps.net/ --recursive
        aws s3 cp ./ s3://scheduler.borg.com.au/ --recursive
        aws s3 cp ./ s3://demo.gc-teleapps.net/ --recursive

AWS SAM Error:
    aws cloudformation delete-stack --stack-name myteststack

Bookmark:
    Ctl+Atl+K
    Ctl+P -> Type Bookmark: <function>

Run the BORG environment in LOCAL:
    Run the below command in the terminal
        export AWS_PROFILE=borg
    In template.yaml, uncomment the borg environment variables.
    Run the below command.
        cd scheduler
        sam local start-api --host 10.10.42.26 --port 3000
