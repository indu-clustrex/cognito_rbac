# Design the Authentication layer with AWS Cognito and Authorization layer with RBAC module

### Authentication vs. Authorization
Authentication : Authentication verifies a user's identity <br/> 
Authorization: Authorization determines the user's level of access and grants access based on that level <br/>

### AWS Cognito
AWS Cognito is a service provided by Amazon Web Services (AWS) that handles user authentication, authorization, and user management for web and mobile applications. It enables developers to add sign-up, sign-in, and access control to their applications quickly and securely.

### Key Benefits of AWS Cognito:
- User Authentication
- User Management
- Scalability
- Security
- Customization
- Social and Enterprise Identity Federation
- Seamless Integration
## Main Components:
- User pool
- Identity pool

### Cognito User pool
An Amazon Cognito user pool is a user directory. With a user pool, your users can sign in to your web or mobile app through Amazon Cognito, or federate through a third-party IdP. Federated and local users have a user profile in your user pool.

