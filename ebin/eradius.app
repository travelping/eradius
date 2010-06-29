{application,eradius,
  [{description,"A short description."},
   {vsn,"0.0.0"},
   {modules,[eradius,
             eradius_dict,
             eradius_acc,
             eradius_lib,
             eradius_server]},
   {registered,[eradius,eradius_acc]},
   {applications,[kernel,stdlib,mnesia]},
   {env,[]}]}
.
