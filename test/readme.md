# Tests

This directory is devoted for tests against the infrastructure of Eradius.

## Using the Logtest

To use this test to its full extend you'll need a system journal from systemd.
Eradius logs its informations via lager and forwards it to journal.
You can then - via journalctl - survey the data.

The 'eradius_logtest' needs to be compiled before one can use it:
Go into the eradius directory and do the following

  `$ erlc test/eradius_logtest.erl`

The test can be used as following:
Start an Erlangshell

    `>application:set_env(lager, handlers, [{lager_journald_backend, []}]).
     >eradius_logtest:start().
     >eradius_logtest:client_test(<<"test">>,{88,88,88,88}).`
     
You now should find something simmilar to the following message in your journal:

    `Feb 13 17:09:52 tpiadmin-HP-EliteBook-8470p beam.smp[11790]: 127.0.0.1:39534 [27]: Access-Request`