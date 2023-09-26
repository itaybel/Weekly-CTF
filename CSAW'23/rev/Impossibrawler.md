This was the third REV challenge of the event. the first two was too easy and I thought they don't deserve a writeup.
We are given 2 files, an exe file and PCK file.
Since I had a little experience reversing games, I knew that we need to reverse a godot game.
Since we are given the PCK file, I right away cloned the `Godot RE tools` repository, and extraced the gd scripts.
When you start the game, you are promted with this text:

![image](https://github.com/itaybel/Weekly-CTF/assets/56035342/efc41e27-a037-41b8-8b5c-fabae145824c)

This means we would need to reverse engineer the game and see how can we win level 2.
When we try to do it manually, we can see that no damage is made to the enemies, so we can't really win.
In this part, there are 2 different ways to approach the challenge:
  1. Patch the game, and change the damage functionallity to instatly kill the enemy.
  2. Understand how the flag is calculated and replicate it.

Since I didn't want to download Godot engine in my computer, I was doing the second approach.
Right away I searched for `csaw` in the source code, and saw this code:

```godot

var rng = RandomNumberGenerator.new()

func _process(delta):
	var mousepos = get_global_mouse_position()
	get_node("Crosshair").position = mousepos

	if enemies_left == 0:
		rng.seed = int(Vals.sd)
		var fbytes = rng.randf()
		Vals.sd = fbytes
		fbytes = str(fbytes)
		var flg = fbytes.to_ascii().hex_encode()
		$CanvasLayer / Label.set_text("csawctf{" + flg + "}")
```

the `_process` command is the function thats gonna be run every tik in the game. it is responsible for global stuff like moving the crosair and checking if the player has won.
We can see that if the player won, it will take `Val.sd`, use that as a seed for the random generator, then it will generate a random number and the flag will be its ascii represntation.
Initially, `Vals.sd` is set to zero, and changed when you beat level 1:
```godot
	if enemies_left == 0:
		rng.seed = Vals.hits ^ enemies_left ^ Vals.playerdmg
		var fbytes = rng.randf()
		Vals.sd = fbytes
		get_tree().change_scene("res://Scenes/Level_2.tscn")
```
it is set to be a random number with a seed of `Vals.hits ^ 20` (since Vals.playerdmg = 20 and enemies_left = 0)
But when we think about it,it doesn't really matter what it is. in the `_process` function of Level2, it will take, Vals.sd, which is a number between 0 and 1, and will transfer it to an int before setting the seed.
This means, that the seed will be always 0!
Now we can run a small script which will create the flag for us, since we know the seed!
```godot


#!/usr/bin/env -S godot -s
extends SceneTre
func _init():

    var rng = RandomNumberGenerator.new()
    rng.seed = 0
    var fbytes = rng.randf()
    fbytes = str(fbytes)
    var flg = fbytes.to_ascii().hex_encode()

    # Print the value of flg to the console
    print("flg: csawctf{", flg + "}")

    quit()
```
And we got the flag!
```
itay@itay-Latitude-3520:~/Desktop/CSAW/impossibrawler/rev$ godot3 -s a.gd
Godot Engine v3.2.3.stable.custom_build - https://godotengine.org
OpenGL ES 3.0 Renderer: Mesa Intel(R) Xe Graphics (TGL GT2)
../src/intel/isl/isl.c:2216: FINISHME: ../src/intel/isl/isl.c:isl_surf_supports_ccs: CCS for 3D textures is disabled, but a workaround is available.

flg: csawctf{302e323032323732}
```
