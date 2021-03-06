#!/bin/bash

set -eo pipefail

if [ -n "$SERVER_BRANCH" ] ; then
  ###################################################################################################################
  # run server test suite
  ###################################################################################################################
  echo "run server test suite"
  git clone -b ${SERVER_BRANCH} https://github.com/mariadb/server ../workdir-server
  cd ../workdir-server
  # don't pull in submodules. We want the latest C/C as libmariadb
  # build latest server with latest C/C as libmariadb
  # skip to build some storage engines to speed up the build
  cmake . -DPLUGIN_MROONGA=NO -DPLUGIN_ROCKSDB=NO -DPLUGIN_SPIDER=NO -DPLUGIN_TOKUDB=NO
  cd libmariadb
  git checkout ${TRAVIS_COMMIT}
  cd ..
  git add libmariadb
  make -j9
  cd mysql-test/
  ./mysql-test-run.pl --suite=main ${TEST_OPTION} --parallel=auto --skip-test=session_tracker_last_gtid

else

  ###################################################################################################################
  # run connector test suite
  ###################################################################################################################
  echo "run connector test suite"

  export MYSQL_TEST_USER=$TEST_DB_USER
  export MYSQL_TEST_HOST=$TEST_DB_HOST
  export MYSQL_TEST_PASSWD=$TEST_DB_PASSWORD
  export MYSQL_TEST_PORT=$TEST_DB_PORT
  export MYSQL_TEST_DB=testc
  export MYSQL_TEST_TLS=$TEST_REQUIRE_TLS
  export SSLCERT=$TEST_DB_SERVER_CERT
  export MARIADB_PLUGIN_DIR=$PWD

  echo "MYSQL_TEST_PLUGINDIR=$MYSQL_TEST_PLUGINDIR"
  if [ -n "$MYSQL_TEST_SSL_PORT" ] ; then
    export MYSQL_TEST_SSL_PORT=$MYSQL_TEST_SSL_PORT
  fi
  cmake . -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCERT_PATH=${SSLCERT}

  if [ "$TRAVIS_OS_NAME" = "windows" ] ; then
    echo "build from windows"
    cmake --build . --config RelWithDebInfo
  else
    echo "build from linux"
    make
  fi

  ls -lrt

  openssl ciphers -v
  cd unittest/libmariadb
  ctest -V
fi
