# EzPi

EzPi unblocks websites and apps that your internet company blocks.

It's for **Linux**. It's tiny (~15 MB), runs in the background, and needs zero setup.

## 1. Install it

Open a terminal in this folder and run:

```sh
sudo ./install.sh
```

That's it. It sets everything up for you.

## 2. Turn it on and off

Just type:

```sh
ezpi
```

- First time you type it → **it turns ON** → `EzPi started successfully.`
- Type `ezpi` again → **it turns OFF** → `EzPi stopped.`

One word. That's the whole thing.

## 3. Is it actually working?

```sh
ezpi --check
```

This tests it live and tells you yes or no.

Want to see the logo?

```sh
ezpi --wizard
```

## Remove it

```sh
sudo ./install.sh --uninstall
```

## What it does (simple version)

When you open a website, your internet company can see the site's **name** and block it. EzPi hides that name so the block can't catch it. Your sites open normally.

It never reads or touches your actual data. It just hides the name.

## Build it yourself (optional)

```sh
make build
make test
```

## License

MIT. Do whatever you want with it. See [LICENSE](LICENSE).

---

*#### Windows, and its users do NOT deserve My Projects.*
