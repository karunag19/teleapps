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