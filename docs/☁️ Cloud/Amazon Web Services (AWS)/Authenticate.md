
Authenticate to AWS with:

```python
aws configure
```

OR env variables (if you’re authing as a resource)

```python
rm -rf ./aws
```

```python
export AWS_ACCESS_KEY_ID=<token>
export AWS_SECRET_ACCESS_KEY=<token>
export AWS_SESSION_TOKEN=<token>
```

OR

```python
aws configure #add access and secret
aws configure set aws_session_token "<session token>"
```

Unset once you are done

```python
unset AWS_ACCESS_KEY_ID
unset AWS_SECRET_ACCESS_KEY
unset AWS_SESSION_TOKEN
```
