## Como compilar ?

 * rustc script.rs

Variaveis mutaveis e imutaveis ?

- let declara uma variável, quando se coloca :i32 isso quer dizer o tipo da variável. Ou seja, i32 é um inteiro com sinal de 32 bits com o valor inicial de 42

- Para declarar uma variavel mutavel basta fazer
```rust
let mut x = 5
```

## Declarando Constantes

- Para declarar uma constante usa-se o `const: u32`

```rust
fn main(){
    const pi = 3.14;
}
```

## Shadowing

- Para usar uma variável imutável com outro valor, basta declarar novamente usando o `let`

```rust
fn main() {
    let number = "T-H-R-E-E"; // Don't change this line
    println!("Spell a number: {number}");

    // TODO: Fix the compiler error by changing the line below without renaming the variable.
    let number = 3;
    println!("Number plus two is: {}", number + 2);
}
```

---

# Data Types

## Scalar Types

### Integer Types
* Cada variante pode armazenar numeros entre −(2<sup>n − 1</sup>) to 2<sup>n - 1</sup> -1. Por exemplo, se usarmos um i8 ele poderá armazenar −(2<sup>7</sup>) to 2<sup>7</sup> − 1, que é igual a −128 até 127

![alt text](image.png)

* Os inteiros também podem ser declarados da seguinte forma

![alt text](image-1.png)

* **Signed:** Podem armazenar valores positivos e negativos
* **Unsigned:** Armazenam apenas valores positivos (e zero)


### Floating-Point Types
* Similar ao inteiro, para declarar um float basta usar o `f32` para 32bits ou `f64` para 64bit

### Numeric Operations

```rust
fn main() {
    // addition
    let sum = 5 + 10;

    // subtraction
    let difference = 95.5 - 4.3;

    // multiplication
    let product = 4 * 30;

    // division
    let quotient = 56.7 / 32.2;
    let truncated = -5 / 3; // Results in -1

    // remainder
    let remainder = 43 % 5;
}
```

### Boolean Type
* Para declarar uma variável do tipo booleano, pode-se fazer o seguine:
    * `let t = true;`
    * `let f: bool = false;`

### Char Type

```rust
fn main() {
    let c = 'z';
    let z: char = 'ℤ'; // with explicit type annotation
    let heart_eyed_cat = '😻';
}
```

#### Compound Types

##### Tuple Type

* Uma tupla é um meio de juntar vários tipos de valores em um único lugar. 

```rust
fn main(){
    let tup: (i32,i64,u8) = (500,6.4,1);
}
```

##### Array Type

```rust
fn main(){
    let a = [a, b, c, d];
}
```

* Outra forma de declarar um array

```rust
#![allow(unused)]
fn main() {
let a: [i32; 5] = [1, 2, 3, 4, 5];
}
```

* Acessando elementos do array:

```rust
fn main() {
    let a = [1, 2, 3, 4, 5];

    let first = a[0];
    let second = a[1];
}
```

## Functions

* Para declarar uma função basta fazer:

```rust
fn nova_Fun({
    println!("Essa é a minha nova função");
})

## Links
- https://doc.rust-lang.org/book/
- https://github.com/rust-lang/rustlings
- https://google.github.io/comprehensive-rust/pt-BR/
- https://github.com/trickster0/OffensiveRust
- https://bishopfox.com/blog/rust-for-malware-development