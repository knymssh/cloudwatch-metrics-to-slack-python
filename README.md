```
$ zip function.zip lambda_function.py
$ aws lambda update-function-code --function-name <name> --zip-file fileb://.function.zip
$ aws lambda invoke --function-name <name> outfile.txt
```