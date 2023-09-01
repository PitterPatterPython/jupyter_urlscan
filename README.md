# jupyter_URLScan.io
A module to help interaction with Jupyter Notebooks and URLScan.io API

------
This is a python module that helps to connect Jupyter Notebooks to various datasets. 
It's based on (and requires) https://github.com/JohnOmernik/jupyter_integration_base 
<3


## Initialization 
----

### Example Inits

#### Embedded mode using qgrid
```
from urlscanio_core import Urlscan
ipy = get_ipython()
Urlscan = Urlscan(ipy, debug=False, pd_display_grid="qgrid")
ipy.register_magics(Urlscan)
```
