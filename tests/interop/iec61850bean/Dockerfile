# IEC61850bean (beanit, Java, Apache-2.0) as the third opinion: the released jars from Maven
# Central, each checked by SHA-256, and a small probe compiled against them.
FROM eclipse-temurin:17-jdk
ARG BEAN=1.9.0
WORKDIR /opt/probe
RUN set -e; \
    fetch() { curl -fsSL -o "$2" "https://repo1.maven.org/maven2/$1/$2" && echo "$3  $2" | sha256sum -c -; }; \
    fetch com/beanit/iec61850bean/${BEAN} iec61850bean-${BEAN}.jar df114f512c4f9855ac977e52d204eb954d6e4f68842ac00f28ce9a678e879bcb; \
    fetch com/beanit/asn1bean/1.12.0 asn1bean-1.12.0.jar 9fa33202dcf1d00f84f289000b0f937aa910b74f771976a625fd638b6f270878; \
    fetch org/slf4j/slf4j-api/1.7.25 slf4j-api-1.7.25.jar 18c4a0095d5c1da6b817592e767bb23d29dd2f560ad74df75ff3961dbde25b79
COPY Probe.java .
RUN javac -cp '*' Probe.java \
 && useradd --create-home --uid 10001 peer
USER peer
ENTRYPOINT ["java", "-cp", "/opt/probe:/opt/probe/*", "Probe"]
CMD ["server", "10102", "/opt/probe/model.icd"]
