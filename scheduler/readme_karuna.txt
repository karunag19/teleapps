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

To start the local web interface
    sam local start-api
    sam local start-api --host 10.10.42.26 --port 3000

To check using curl:
    curl http://10.10.42.26:3000/hello
    Note: you need to specify the method (getec2region), if not specify it through an error "Missing Authentication Token"

To create packages:
    sam package --template-file <template file name> --output-template-file <output file name> --s3-bucket <s3 bucket name>
    sam package --template-file template.yaml --output-template-file deploy.yaml --s3-bucket deployment-teleapps-schedule

To deploy packages:
    sam deploy --template-file deploy.yaml --stack-name MySAMLambdaStack --capabilities CAPABILITY_IAM
    sam deploy --template-file deploy.yaml --stack-name TeleApps-Schedule --capabilities CAPABILITY_IAM

Reference:
    https://github.com/awslabs/serverless-application-model/blob/master/versions/2016-10-31.md#awsserverlessfunction
    
Install Packages as Layer:
    cd dependencies/python/lib/python3.8/site-packages/
    pip install <package name> -t .
    e.g
    pip install jsonschema -t .
