# IDA Python API Notes

## idautils
### Functions(start=None, end=None)
Get a list of functions  
start: start address (default: inf.min_ea)  
end: end address (default: inf.max_ea)  
return: list of function entrypoints between start and end

### Chunks(start)
Get a list of function chunks See also ida_funcs.func_tail_iterator_t  
start: address of the function  
return: list of function chunks (tuples of the form (start_ea, end_ea)) belonging to the function


### Heads(start=None, end=None)
Get a list of heads (instructions or data items)  
start: start address (default: inf.min_ea)  
end: end address (default: inf.max_ea)  
return: list of heads between start and end  

### XrefsFrom(ea, flags=0)
Return all references from address 'ea'  
ea: Reference address  
flags: one of ida_xref.XREF_ALL (default), ida_xref.XREF_FAR, ida_xref.XREF_DATA  
Example:
```
for xref in XrefsFrom(here(), 0):  
    print(xref.type, XrefTypeName(xref.type), 'from', hex(xref.frm), 'to', hex(xref.to))  
```

### XrefsTo(ea, flags=0)
Return all references to address 'ea'  
ea: Reference address  
flags: one of ida_xref.XREF_ALL (default), ida_xref.XREF_FAR, ida_xref.XREF_DATA  
Example:
```
for xref in XrefsTo(here(), 0):
    print(xref.type, XrefTypeName(xref.type), 'from', hex(xref.frm), 'to', hex(xref.to))
```

## ida_funcs

### get_func(ea)
Get pointer to function structure by address.  
ea: any address in a function - not necessarily entrypoint  
return: ptr to a function or nullptr. This function returns a function entry chunk.
