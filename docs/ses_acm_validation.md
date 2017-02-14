# flake8: noqa
Creating an Automated AWS Certificate Manager Verification Pipeline
-------------------------------------------------------------------

AWS Certification Manager (ACM) requires verification of the ownership of the domain name, 
or alternatively, of the super-domain of the domain that you want the certificate for. 
Currently the only way this is done is through email to the following addresses,

* Whois domain, technical, and administrative contact
* administrator, hostmaster, postmaster, webmaster, and admin at the requested domain or the super-domain if specified.

http://docs.aws.amazon.com/acm/latest/userguide/gs-acm-validate. html

![alt text](images/ses_acm_ses_sns.png "Certificate manager to simple email service pipeline")

Using the super-domain as the validation domain
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

With a lot of hosted zones we could end up doing extra work to add MX records to everyone 
of them, luckily, we can use the super-domain instead of the actual domain to do verifications. 
This means that instead of requiring setting up mail every hosted zone, we can simply set all 
the sub-domains to verify on the super-domain. For example, mysite.mysubdomain.mydomain.com 
sets validation domain to mydomain.com, so the verification emails will not be set to 
admin@mysite.mysubdomain.superdomain.com, but instead to admin@superdomain.com.

See http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/ aws-resource-certificatemanager-certificate.html

    Type: "AWS::CertificateManager::Certificate"
    Properties:
        DomainName: String
        DomainValidationOptions:
        − DomainValidationOptions
        SubjectAlternativeNames:
        − String
        Tags:
        − Resource Tag

Domain validation with an external mail server
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To achieve this the most straightforward way would be to set up a mail MX record in route53 
for your domain or super-domain pointing at your existing mail service.

Domain validation using SES
~~~~~~~~~~~~~~~~~~~~~~~~~~~

We can set up Amazon Simple Email Service (SES) to work together with ACM. 
First we setup a route 53 MX record on the super-domain hosted zone to use the Simple Email Service (SES). 
Add an SES ruleset that sends mail to an S3 bucket and triggers a Lambda function that will 
forward the email from the bucket. This way the verification email can be sent on to real administrators.

Using the SESLambdaForwarder cloudformation stack
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

There's a cloudformation template available for doing this, 
see `the SES lambda forwarder template <SESLambdaForwarder.yaml>`_

When creating this stack you can set the email addresses to forward, and a set of 
forwarding addresses. This cloudformation sets up a lambda function and a S3 bucket 
with default 3 day deletion policy. We need to setup SES on the domain we want to 
receive mail on since it doesnt have cloudformation support, but luckily this is 
straightforward.

> Note, SES may bounce emails when sending to meta-email addresses such as for groups. See `the SES FAQ <http://docs.aws.amazon.com/ses/latest/DeveloperGuide/e-faq-bn.html>`_ for more details.

Setup SES on the mail domain
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* Create an SES domain for the base domain name superdomain.com.
* Let the SES domain creation set route 53 entries for verification and MX, eg in the superdomain.com hosted zone, superdomain.com MX 10 inbound−smtp.eu−west−1.amazonaws.com.
* Create a SES rule et to send emails to the S3 bucket.
* When creating certificates, use superdomain.com as the validation domain, this means admin@superdomain.com will be emailed when we create any sub-domain something.somewhere.superdomain.com.
* While the stack requiring an ACM SSL certificate is being created, the forwarding addresses should all receive a validation email.
