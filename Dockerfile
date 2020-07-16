#       Copyright 2017-2020 IBM Corp All Rights Reserved

#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at

#       http://www.apache.org/licenses/LICENSE-2.0

#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

FROM alpine:latest AS cert-extractor
ARG keycloak_connection_string
ARG extract_keycloak_cert
RUN echo "Extract cert: '$extract_keycloak_cert' - Connection string: '$keycloak_connection_string'" && touch keycloak.pem
RUN if [ "$extract_keycloak_cert" = "true" ]; then apk add openssl && openssl s_client -showcerts -connect ${keycloak_connection_string} </dev/null 2>/dev/null|openssl x509 -outform PEM > keycloak.pem ; fi

FROM maven:3.6-jdk-11-slim AS build
COPY . /usr/
RUN mvn -f /usr/pom.xml clean package

FROM openliberty/open-liberty:kernel-java11-openj9-ubi
ARG extract_keycloak_cert
USER root

# Following line is a workaround for an issue where sometimes the server somehow loads the built-in server.xml,
# rather than the one I copy into the image.  That shouldn't be possible, but alas, it appears to be some Docker bug.
RUN rm /opt/ol/wlp/usr/servers/defaultServer/server.xml

COPY --chown=1001:0 server.xml /config/server.xml
COPY --chown=1001:0  --from=build /usr/target/notification-slack-1.0-SNAPSHOT.war /config/apps/NotificationSlack.war
COPY --chown=1001:0 key.jks /config/resources/security/key.jks
# COPY --chown=1001:0 ltpa.keys /output/resources/security/ltpa.keys

COPY --from=cert-extractor /keycloak.pem /tmp/keycloak.pem
RUN chown -R 1001:0 config/
USER 1001
RUN if [ "$extract_keycloak_cert" = "true" ]; then keytool -import -v -trustcacerts -alias keycloak -file /tmp/keycloak.pem -keystore /opt/ol/wlp/usr/servers/defaultServer/resources/security/key.jks --noprompt --storepass passw0rd ; fi
RUN configure.sh
