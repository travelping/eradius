# eradius

This fork of eradius is a radical deviation from the original
Jungerl code. It contains a generic RADIUS client, support for 
several authentication mechanisms and dynamic configuration
(it implements the `config_change/3` application callback).

We should probably rename it to avoid confusion.

## Building eradius

We use [tetrapak](github.com/fjl/tetrapak) to build eradius.
Tetrapak is required to build the dictionaries.

