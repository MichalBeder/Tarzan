#!/usr/bin/env bash
export SPARK_SUBMIT_OPTS="-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005"
spark-shell --jars ./ndx-spark-shell/target/ndx-spark-shell-0.9-SNAPSHOT.jar
# run intellij debugger
