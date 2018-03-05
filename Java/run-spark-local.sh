#!/usr/bin/env bash
mvn clean package -DskipTests
spark-shell --jars ./ndx-spark-shell/target/ndx-spark-shell-0.9-SNAPSHOT.jar
