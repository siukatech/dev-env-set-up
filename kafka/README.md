# kafka
docker-compose collection for dev


## 01-ssl-certificate
The `ssl_creds_gen_01.sh` is used to generate the `keystore` and `truststore` files for kafka's SSL protocol.  


### Variables in script
These are the variable that can be refined in the script.  

| Variable | Value | Remarks |
| - | - | - |
| HOSTNAME | localhost | Hostname of certificate |
| DAYS | 3650 | No of days that certificate will be expired | 
| PASSWORD | kafkapwd | Password for truststore, keystore and certificate |
| COUNTRY | HK | Country in certificate |
| STATE | HK | State in certificate |
| LOCALITY | Hong\ Kong | Locality in certificate, '\' is used to escape the space |
| - | - | - |
| ORG_CA | CA\ Root\ 01 | Organization in CA Root certificate |
| OU_CA | CA_ROOT_01 | Organization Unit in CA Root certificate |
| ORG_CERT | Cert\ 01 | Organization in our certificate |
| OU_CERT | CERT_01 | Organization Unit in our certificate |
| - | - | - |
| SUBJ_CA | /C=\${COUNTRY}/ST=${STATE}<br/>/L=\${LOCALITY}/O=\${ORG_CA}<br/>/OU=\${OU_CA} | Subject in CA Root certificate |
| SUBJ_CERT | /C=\${COUNTRY}/ST=\${STATE}<br/>/L=\${LOCALITY}<br/>/O=\${ORG_CERT}/OU=\${OU_CERT} | Subject in our certificate |
| DNAME_CA | CN=\${CN_CA}, OU=\${OU_CA}<br/>, O=\${ORG_CA}, L=\${LOCALITY}<br/>, S=\${STATE}, C=\${COUNTRY} | Distinguished name (dname) in CA Root certificate |


### Steps in ssl_creds_gen_01.sh
#### Step 1
**Command**
```shell
keytool -keystore server.keystore.jks -alias "${HOSTNAME}" -validity "${DAYS}" -keyalg RSA -genkey -dname "${DNAME_CA}" -storepass "${PASSWORD}" -keypass "${PASSWORD}"
```

**Output**
- server.keystore.jks - keystore for servers


#### Step 2
**Command**
```shell
openssl req -new -x509 -keyout ca-key -out ca-cert -days "${DAYS}" -subj "${SUBJ_CA}" -passin pass:"${PASSWORD}" -passout pass:"${PASSWORD}"

keytool -keystore server.truststore.jks -alias CARoot -import -file ca-cert -dname "${DNAME_CA}" -storepass "${PASSWORD}" -noprompt

keytool -keystore client.truststore.jks -alias CARoot -import -file ca-cert -dname "${DNAME_CA}" -storepass "${PASSWORD}" -noprompt
```

**Output**
- ca-key - RSA key for CA Root certificate
- ca-cert - CA Root certificate
- server.truststore.jks - truststore for server
- client.truststore.jks - truststore for client


#### Step 3
**Command**
```shell
keytool -keystore server.keystore.jks -alias "${HOSTNAME}" -certreq -file cert-file -storepass "${PASSWORD}"

openssl x509 -req -CA ca-cert -CAkey ca-key -in cert-file -out cert-signed -days "${DAYS}" -CAcreateserial -subj "${SUBJ_CERT}" -passin pass:"${PASSWORD}"

keytool -keystore server.keystore.jks -alias CARoot -import -file ca-cert -storepass "${PASSWORD}" -noprompt

keytool -keystore server.keystore.jks -alias "${HOSTNAME}" -import -file cert-signed -storepass "${PASSWORD}" -noprompt
```

**Output**
- cert-file - export certificate file from server's keystore
- ca-cert.srl - serial no by CAcreateserial during signing
- cert-signed - signed certificate
- server.keystore.jks - keystore for servers


#### Step 4
**Command**
```shell
echo "${CREDS_VAL}" >> "${CREDS_FILE}"
```

**Output**
- ssl_cert.creds - CREDENTIALS credentials file for kafka configuration `KAFKA_SSL_KEYSTORE_CREDENTIALS`, `KAFKA_SSL_KEY_CREDENTIALS`, `KAFKA_SSL_TRUSTSTORE_CREDENTIALS`



## 11-confluentinc-kafka
### 01-config
#### 01-zookeeper
The `zookeeper_server_jaas.conf` is the Zookeeper Server configuration.  

> !!!user_[username]="[password]" <span style="color:red">CAN BE USED</span> in Server.  

There are 3 sections inside the `zookeeper_server_jaas.conf`.  
- Server
- QuorumServer
- QuorumLearner

Each of them contains `DigestLoginModule` and `ScramLoginModule` for external services to access.  
- org.apache.zookeeper.server.auth.DigestLoginModule - `PLAINTEXT`
- org.apache.kafka.common.security.scram.ScramLoginModule - `SASL_SSL`


#### 11-kafka
The `kafka_server_jaas.conf` is the Kafka Server configuration for producer and consumer to connect.  

There are 3 sections inside the `kafka_server_jaas.conf`.  
- KafkaServer
- KafkaClient
- Client

The `KafkaServer` contains `DigestLoginModule` and `ScramLoginModule` that is the configuration for producer and consumer to connect.  
- org.apache.kafka.common.security.plain.PlainLoginModule - `SASL_PLAINTEXT`
- org.apache.kafka.common.security.scram.ScramLoginModule - `SASL_SSL`

The `KafkaClient` contains `DigestLoginModule` and `ScramLoginModule` that is the client config used to connect Kafka.  
- org.apache.kafka.common.security.plain.PlainLoginModule - `SASL_PLAINTEXT`
- org.apache.kafka.common.security.scram.ScramLoginModule - `SASL_SSL`

The `Client` contains `DigestLoginModule` and `ScramLoginModule` and `DigestLoginModule` that is the Zookeeper Client configuration to connect Zookeeper.  
- org.apache.kafka.common.security.plain.PlainLoginModule - `SASL_PLAINTEXT`
- org.apache.kafka.common.security.scram.ScramLoginModule - `SASL_SSL`
- org.apache.zookeeper.server.auth.DigestLoginModule - `PLAINTEXT`


The `PlainLoginModule` is referring the protocol `SASL_PLAINTEXT`.  

> !!!username="[username]" and password="[password]" <span style="color:red">IS NOT REQUIRED</span>.
> 
> !!!user_[username]="[password]" <span style="color:red">IS ALLOWED</span> for users set-up.


The `ScramLoginModule` is referring the protocol `SASL_SSL`.  

> username="[username]" and password="[password]" IS REQUIRED for set-up.
> 
> But the actual user creation is performed by executing a command, e.g.:  

```shell
kafka-configs --zookeeper zookeeper-x01:2181 --alter --add-config 'SCRAM-SHA-256=[iterations=4096,password=ben1-secret]' --entity-type users --entity-name ben1
```


### 11-docker
#### Self-defined naming and custom ports are not working
We can ONLY use `PLAINTTEXT` and `SSL`.  
Cannot use self-defined names, like `INTERNAL`.  
Using other ports are not working too.

According to section `Required Kafka configurations for ZooKeeper mode` on https://docs.confluent.io/platform/current/installation/docker/config-reference.html#required-ak-configurations-for-zk-mode.  
The SSL:// and SASL_SSL:// MUST be used.  
```text
If using the TLS/SSL or SASL protocol, the endpoint value must specify the protocols in the following formats:

SSL: SSL:// or SASL_SSL://
SASL: SASL_PLAINTEXT:// or SASL_SSL://
```


#### Environment variable conversion rules
##### Basic
Confluent kafka converts the environment variables to proper configuration in properties, section `Kafka configuration` on https://docs.confluent.io/platform/current/installation/docker/config-reference.html#ak-configuration.  
```text
Convert the properties file variables according to the following rules and use them as Docker environment variables:

Prefix Kafka component properties with KAFKA_. For example, metric.reporters is a Kafka property so should be converted to KAFKA_METRIC_REPORTERS.
Prefix Confluent component properties for cp-server with CONFLUENT_ for For example, confluent.metrics.reporter.bootstrap.servers is a Confluent Enterprise feature property, so, it should be converted to CONFLUENT_METRICS_REPORTER_BOOTSTRAP_SERVERS.
Convert to upper-case.
Replace a period (.) with a single underscore (_).
Replace an underscore (_) with double underscores (__).
Replace a dash (-) with triple underscores (___).
```


##### Deep dive
Here is the confluent scripts execution sequence,  
configure -> ensure -> launch  

**Reference**
https://docs.confluent.io/platform/current/installation/docker/development.html#cp-image-bootup-process  


`KAFKA_SSL_XXX_CREDENTIALS` is used instead of `KAFKA_SSL_XXX_PASSWORD`, the `kafka-image/kafka/include/etc/confluent/docker/configure` script exports all `_PASSWORD` specifically.  

**Reference**  
https://github.com/confluentinc/kafka-images/blob/master/kafka/include/etc/confluent/docker/configure  


Refer to the `dub.py` from `confluent-docker-utils`, https://github.com/confluentinc/confluent-docker-utils/blob/master/confluent/docker_utils/dub.py.  
The environment variable names will be taken off the prefix, eg `KAFKA_` and converted to lower case.  

The execution sequence is,  
def main() -> def fill_and_write_template -> def parse_log4j_loggers or def env_to_props
```python
def main():
  ...
  template = actions.add_parser('template', description='Generate template from env vars.')
  ...
  if args.action == "template":
      success = fill_and_write_template(args.input, args.output)
  ...
```

```python
def fill_and_write_template(template_file, output_file, context=os.environ):
  ...
  j2_env.globals['parse_log4j_loggers'] = parse_log4j_loggers
  j2_env.globals['env_to_props'] = env_to_props
  ...
```

```python
def env_to_props(env_prefix, prop_prefix, exclude=[]):
  ...
  if env_name not in exclude and env_name.startswith(env_prefix):
      raw_name = env_name[len(env_prefix):].lower()
      prop_dot = '.'.join(pattern.split(raw_name))
      prop_dash = '-'.join(prop_dot.split('___'))
      prop_underscore = '_'.join(prop_dash.split('__'))
      prop_name = prop_prefix + prop_underscore
      props[prop_name] = val
  ...
```



<!--
#### SASL_SSL
**truststore.jks**
```
../01-ssl-certificate/server.truststore.jks  
kafkapwd
```

**keystore.jks**
```
../01-ssl-certificate/server.keystore.jks  
kafkapwd
```
-->


#### Services in docker compose yaml
There are 3 services declared in the yaml file.  
- zookeeper-add-kafka-users
- zookeeper-03-04-03
- kafka-03-04-03


##### zookeeper-add-kafka-users
This is using the image `confluentinc/cp-kafka:7.5.3` to connect the zookeeper to create the users by configuration below.  

```yaml
...
zookeeper-add-kafka-users:
    ...
    container_name: zookeeper-add-kafka-users
    depends_on:
        zookeeper-03-04-03:
        condition: service_started
    command: "bash -c 'sleep 5 && \ 
                cub zk-ready zookeeper-x01:2181 100 && \
                cub zk-ready zookeeper-x01:2181 100 && \
                kafka-configs --zookeeper zookeeper-x01:2181 --alter --add-config 'SCRAM-SHA-256=[iterations=4096,password=ben1-secret]' --entity-type users --entity-name ben1 && \
                kafka-configs --zookeeper zookeeper-x01:2181 --alter --add-config 'SCRAM-SHA-256=[iterations=4096,password=sam1-secret]' --entity-type users --entity-name sam1 \
            '"
    ...
...
```

**Reference:**  
https://github.com/hussein-joe/kafka-security-ssl-sasl/blob/master/sasl-scram/docker-compose-scram.yml


##### zookeeper-03-04-03
This is using the image `confluentinc/cp-zookeeper:7.5.3` to launch the zookeeper.  

```yaml
...
zookeeper-03-04-03:
  ...
  environment:
    # ZOOKEEPER_LOG4J_ROOT_LOGLEVEL: DEBUG
    ZOOKEEPER_CLIENT_PORT: 2181
    ZOOKEEPER_TICK_TIME: 2000
    ZOOKEEPER_AUTH_PROVIDER_SASL: org.apache.zookeeper.server.auth.SASLAuthenticationProvider
    ZOOKEEPER_REQUIRE_CLIENT_AUTH_SCHEME: sasl
    # ZOOKEEPER_AUTHPROVIDER.1: org.apache.zookeeper.server.auth.SASLAuthenticationProvider
    # ZOOKEEPER_JAAS_LOGIN_RENEW: 3600000
    # quorum.auth.enableSasl=true
    # quorum.auth.learnerRequireSasl=true
    # quorum.auth.serverRequireSasl=true
    ZOOKEEPER_QUORUM_AUTH_ENABLE_SASL: 'true'
    ZOOKEEPER_QUORUM_AUTH_LEARNER_REQUIRE_SASL: 'true'
    ZOOKEEPER_QUORUM_AUTH_SERVER_REQUIRE_SASL: 'true'
    # ZOOKEEPER_SSLA.CELENG: true
    # # ZOOKEEPER_OPTS: "-Djava.security.auth.login.config=/etc/kafka/config/zookeeper_server_jaas.conf"
    # KAFKA_OPTS: "-Djava.security.auth.login.config=/etc/kafka/config/zookeeper_server_jaas.conf
    #              -Dzookeeper.4lw.commands.whitelist=ruok
    #             "
    KAFKA_OPTS: "-Djava.security.auth.login.config=/etc/kafka/config/zookeeper_server_jaas.conf"
    # healthcheck:
    #   # # test: ['CMD-SHELL','cub zk-ready zookeeper-x01:2181 120']
    #   # test: cub zk-ready zookeeper-x01:2181 100
    #   # 
    #   # https://github.com/confluentinc/cp-docker-images/issues/358#issuecomment-1087852715
    #   # "ruok" is required to add to zookeeper.4lw.commands.whitelist
    #   test: ['CMD-SHELL','echo "ruok" | nc -w 2 127.0.0.1 2181 | grep imok']
    #   interval: 3s
    #   retries: 2
    #   start_period: 3s
    #   timeout: 3s
  ...
...
```


##### kafka-03-04-03
This is using the image `confluentinc/cp-kafka:7.5.3` to launch the kafka worker node.  

```yaml
...
kafka-03-04-03:
  ...
  environment:
    # https://doc.confluent.io/platform/current/installtion/docker/operations/logging.html
    # KAFKA_LOG4J_ROOT_LOGLEVEL: DEBUG
    # KAFKA_LOG4J_TOOLS_LOGLEVEL: DEBUG
    # KAFKA_LOG4J_LOGGERS: 'kafka=DEBUG,kafka.controller=DEBUG'

    KAFKA_BROKER_ID: 1
    KAFKA_BROKER_RACK: 'r1'
    KAFKA_ZOOKEEPER_CONNECT: 'zookeeper-x01:2181'
    # KAFKA_ZOOKEEPER_CONNECT: 'zookeeper:2181/kafka'
    # ZOOKEEPER_SASL_ENABLE: 'false'
    # KAFKA_ZOOKEEPER_SSL_CLIENT_ENABLE: 'true'

    # KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1
    # KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS: 0


    # # KAFKA_LISTENER_SECURITY_PROTOCOL_MAP: PLAINTEXT:PLAINTEXT,SSL:SSL,SASL_PLAINTEXT:SASL_PLAINTEXT,SASL_SSL:SASL_SSL
    # KAFKA_LISTENER_SECURITY_PROTOCOL_MAP: CLEAR:PLAINTEXT,SSL:SSL,INTERNAL:SASL_PLAINTEXT,EXTERNAL:SASL_SSL,DOCKER:PLAINTEXT
    KAFKA_LISTENER_SECURITY_PROTOCOL_MAP: CLEAR:PLAINTEXT,SSL:SSL,INTERNAL:SASL_PLAINTEXT,EXTERNAL:SASL_SSL

    # KAFKA_LISTENERS: PLAINTEXT://:9092,SSL://:9093,SASL_PLAINTEXT://:9094,SASL_SSL://:9095
    # KAFKA_LISTENERS: PLAINTEXT://0.0.0.0:9092,SSL://0.0.0.0:9093,SASL_PLAINTEXT://0.0.0.0:9094,SASL_SSL://0.0.0.0:9095
    KAFKA_LISTENERS: CLEAR://0.0.0.0:9092,SSL://0.0.0.0:9093,INTERNAL://0.0.0.0:9094,EXTERNAL://0.0.0.0:9095

    # # KAFKA_SECURITY_INTER_BROKER_PROTOCOL: SSL
    # KAFKA_SECURITY_INTER_BROKER_PROTOCOL: SASL_PLAINTEXT
    # KAFKA_INTER_BROKER_LISTENER_NAME: PLAINTEXT
    # KAFKA_INTER_BROKER_LISTENER_NAME: SASL_SSL
    # KAFKA_INTER_BROKER_LISTENER_NAME: SASL_PLAINTEXT
    KAFKA_INTER_BROKER_LISTENER_NAME: INTERNAL
    # KAFKA_INTER_BROKER_PROTOCOL: SASL_SSL

    # KRaft mode only
    # KAFKA_CONTROLLER_LISTENER_NAMES: EXTERNAL

    # # KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://localhost:9092,SSL://localhost:9093,SASL_PLAINTEXT://localhost:9094,SASL_SSL://localhost:9095
    # KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://1.1.1.1:9092,SSL://1.1.1.1:9093,SASL_PLAINTEXT://1.1.1.1:9094,SASL_SSL://1.1.1.1:9095
    # # KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://localhost:9092,SSL://localhost:39493
    # KAFKA_ADVERTISED_LISTENERS: CLEAR://kafka-x01:9092,SSL://kafka-x01:9093,INTERNAL://kafka-x01:9094,EXTERNAL://kafka-x01:9095
    # KAFKA_ADVERTISED_LISTENERS: CLEAR://kafka-x01:9092,SSL://kafka-x01:9093,INTERNAL://kafka-x01:9094,EXTERNAL://${DOCKER_HOST_IP:-127.0.0.1}:9095,DOCKER://host.docker.internal:9095
    # KAFKA_ADVERTISED_LISTENERS: CLEAR://kafka-x01:9092,SSL://kafka-x01:9093,INTERNAL://kafka-x01:9094,EXTERNAL://${DOCKER_HOST_IP:-127.0.0.1}:9095
    # # KAFKA_ADVERTISED_LISTENERS: CLEAR://1.1.1.1:9092,SSL://1.1.1.1:9093,INTERNAL://1.1.1.1:9094,EXTERNAL://${DOCKER_HOST_IP:-127.0.0.1}:9095
    KAFKA_ADVERTISED_LISTENERS: CLEAR://${DOCKER_HOST_IP:-127.0.0.1}:9092,SSL://${DOCKER_HOST_IP:-127.0.0.1}:9093,INTERNAL://${DOCKER_HOST_IP:-127.0.0.1}:9094,EXTERNAL://${DOCKER_HOST_IP:-127.0.0.1}:9095

    # KAFKA_SECURITY_PROTOCOL: SSL
    # KAFKA_SECURITY_PROTOCOL: SASL_SSL

    # KAFKA_SASL_ENABLED_MECHANISMS: PLAIN
    KAFKA_SASL_ENABLED_MECHANISMS: PLAIN,SCRAM-SHA-256

    KAFKA_SASL_MECHANISM_INTER_BROKER_PROTOCOL: PLAIN
    # KAFKA_SASL_MECHANISMS: SCRAM-SHA-256

    # KAFKA_LISTENER_NAME_INTERNAL_SASL_ENABLED_MECHANISMS: PLAIN
    # KAFKA_LISTENER_NAME_EXTERNAL_SASL_ENABLED_MECHANISMS: SCRAM-SHA-256
    # KAFKA_LISTENER_NAME_EXTERNAL_SASL_MECHANISM: SCRAM-SHA-256
    KAFKA_SASL_MECHANISM_CONTROLLER_PROTOCOL: SCRAM-SHA-256

    KAFKA_SSL_KEYSTORE_FILENAME: server.keystore.jks
    # KAFKA_SSL_KEYSTORE_PASSWORD: "kafkapwd"
    # KAFKA_SSL_KEY_PASSWORD: "kafkapwd"
    KAFKA_SSL_KEYSTORE_CREDENTIALS: ssl_cert.creds
    KAFKA_SSL_KEY_CREDENTIALS: ssl_cert.creds

    KAFKA_SSL_TRUSTSTORE_FILENAME: server.truststore.jks
    # KAFKA_SSL_TRUSTSTORE_PASSWORD: "kafkapwd"
    KAFKA_SSL_TRUSTSTORE_CREDENTIALS: ssl_cert.creds

    # certificates in 03-04-00-kafka-cert are working
    # KAFKA_SSL_KEYSTORE_FILENAME: kafka-03-04.keystore.jks
    # KAFKA_SSL_KEYSTORE_CREDENTIALS: kafka-03-04.creds
    # KAFKA_SSL_KEY_CREDENTIALS: kafka-03-04.creds

    # KAFKA_SSL_TRUSTSTORE_FILENAME: kafka-03-04.truststore.jks
    # KAFKA_SSL_TRUSTSTORE_CREDENTIALS: kafka-03-04.creds

    KAFKA_SSL_ENDPOINT_IDENTIFICATION_ALGORITHM: ""
    KAFKA_SSL_CLIENT_AUTH: "required"

    # KAFKA_AUTHORIZER_CLASS_NAME: kafka.security.auth.SimpleAclAuthorizer
    # KAFKA_SUPER_USERS: User:admin;User:producer

    KAFKA_OPTS: "-Djava.security.auth.login.config=/etc/kafka/config/kafka_server_jaas.conf"
    ...
...
```


#### Run
**Command**
```shell
#cd ./21-confluentinc-kafka && docker-compose -f docker-compose-03-04-03.yml up -d
cd ./kafka/11-confluentinc-kafka/11-docker
docker-compose -f docker-compose-03-04-03.yml rm -fsv
docker-compose -f docker-compose-03-04-03.yml up -d
```


## 21-wurstmeister-kafka
Not ready yet.

<!-- -->
### 01-config
#### 01-zookeeper
The `zookeeper_server_jaas_sasl_plaintext.conf` is the Zookeeper Server configuration.  
There is 1 section inside the conf file.
- zookeeper

The block contains `PlainLoginModule` to allow `SASL` login.  
- org.apache.kafka.common.security.plain.PlainLoginModule - SASL_PLAINTEXT


#### 11-kafka
The `kafka_server_jaas_sasl_plaintext.conf` is the Kafka Server configuration.  
There are 2 sections inside the conf file.
- KafkaServer
- KafkaClient

The block contains `PlainLoginModule` to allow `SASL` login.  
- org.apache.kafka.common.security.plain.PlainLoginModule - SASL_PLAINTEXT



### 11-docker
#### Run
**Command**
```shell
#cd ./21-wurstmeister-kafka && docker-compose -f docker-compose-41-04.yml up -d
cd ./kafka/21-wurstmeister-kafka/11-docker
docker-compose -f docker-compose-04-41-04.yml rm -fsv
docker-compose -f docker-compose-04-41-04.yml up -d
```

<!-- -->


## 31-akhq
Official website https://akhq.io


### akhq-0.25.1-all.jar
akhq jar can be found on https://github.com/tchiotludo/akhq/releases and installation guide is https://akhq.io/docs/installation.html, search section `Stand Alone`.  


### start-gui.sh
Shortcut to launch application with command below.  
```shell
java -Dmicronaut.config.files=./application.yml -jar akhq-0.25.1-all.jar
```


### application.yml
There are 4 connections defined in the `application.yml`.  
- ssl_not_require_jaas
- sasl_plain
- sasl_ssl_sam1
- sasl_ssl_ben1
- sasl_ssl_ivan1

