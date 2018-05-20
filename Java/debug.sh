#!/usr/bin/env bash
# debugging is possible only in spark local mode
export SPARK_SUBMIT_OPTS="-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005"
spark-shell --jars ./ndx-spark-shell/target/ndx-spark-shell-1.0.jar
# run debugger
