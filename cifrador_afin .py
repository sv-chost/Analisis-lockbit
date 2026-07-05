#!/usr/bin/env python3
"""
Cifrador afin - replica el mecanismo usado por LockBit para ofuscar strings
El desarrollador del malware uso este tipo de transformacion para que los
nombres de las DLLs no aparezcan en texto plano dentro del ejecutable.

Uso: python3 cifrador_afin.py
"""

def cifrar_string(texto, clave, multiplicador):
    """
    Cifra un string usando transformacion afin modular.
    
    Para encontrar la transformacion inversa (cifrado -> original),
    necesitamos la funcion inversa modular de 'multiplicador' en mod 127.
    
    El ultimo byte del resultado siempre sera la clave,
    actuando como terminador del bloque (produce 0 al descifrar).
    
    Args:
        texto        : string a cifrar (ej: "kernel32.dll")
        clave        : constante k del algoritmo (ej: 99)
        multiplicador: factor de multiplicacion (ej: 11)
    
    Returns:
        lista de bytes cifrados
    """
    # Calculamos el inverso modular del multiplicador en mod 127
    # Necesario para que la operacion sea reversible
    inv = inverso_modular(multiplicador, 0x7f)
    if inv is None:
        raise ValueError(
            f"El multiplicador {multiplicador} no tiene inverso en mod 127. "
            f"Elige un multiplicador coprimo con 127."
        )
    
    bytes_cifrados = []
    for caracter in texto:
        b = ord(caracter)
        # Operacion inversa: encontramos x tal que ((clave - x) * mult) % 127 = b
        # Despejando x: x = clave - (b * inv) % 127
        x = (clave - (b * inv) % 0x7f) % 0x7f
        bytes_cifrados.append(x)
    
    # El ultimo byte siempre es la clave (produce 0 al descifrar = terminador nulo)
    bytes_cifrados.append(clave)
    return bytes_cifrados


def descifrar_bloque(bytes_cifrados, clave, multiplicador):
    """
    Descifra un bloque de bytes usando la misma transformacion afin
    que usa LockBit en sus loops do/while.
    
    Replica exactamente:
        byte_nuevo = ((clave - byte_original) * multiplicador % 0x7f + 0x7f) % 0x7f
    
    Args:
        bytes_cifrados: lista de bytes tal como aparecen en Ghidra
        clave         : constante visible en el loop (ej: 99)
        multiplicador : constante visible en el loop (ej: 0xb)
    
    Returns:
        bytearray con el string descifrado
    """
    resultado = bytearray()
    for b in bytes_cifrados:
        byte_nuevo = ((clave - b) * multiplicador % 0x7f + 0x7f) % 0x7f
        resultado.append(byte_nuevo)
    return resultado


def inverso_modular(a, m):
    """
    Calcula el inverso modular de 'a' en mod 'm' usando el
    algoritmo extendido de Euclides.
    
    El inverso modular de 'a' es el numero 'x' tal que (a * x) % m = 1.
    Solo existe si a y m son coprimos (mcd(a, m) = 1).
    
    En nuestro caso: 127 es primo, asi que cualquier numero
    entre 1 y 126 tiene inverso modular en mod 127.
    """
    if m == 1:
        return 0
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 % m0


def mostrar_bytes_como_ghidra(bytes_lista, nombre_variable):
    """
    Muestra los bytes en el formato exacto que Ghidra genera,
    para que el lector pueda comparar con lo que ve en el decompilador.
    """
    print(f"\n  // Asi apareceria en Ghidra:")
    print(f"  {nombre_variable}[0] = 0x{bytes_lista[0]:02x};")
    for i, b in enumerate(bytes_lista[1:-1], 1):
        print(f"  {nombre_variable}[{i}] = 0x{b:02x};")
    print(f"  {nombre_variable}[0x{len(bytes_lista)-1:x}] = {bytes_lista[-1]};  "
          f"// <-- este es la clave: {bytes_lista[-1]}")


def main():
    print("=" * 60)
    print("  Cifrador/Descifrador Afin - Mecanismo LockBit")
    print("=" * 60)
    print()
    print("  Este script replica el algoritmo que LockBit usa para")
    print("  ocultar nombres de DLLs dentro del ejecutable.")
    print("  Los bytes cifrados son los que veriamos en Ghidra.")
    print()

    # -----------------------------------------------------------
    # PARTE 1: CIFRADO
    # El lector ingresa su propio string para cifrarlo
    # -----------------------------------------------------------
    print("-" * 60)
    print("  PARTE 1: CIFRADO")
    print("  Convierte un string legible en bytes ofuscados")
    print("-" * 60)
    print()

    texto = input("  Ingresa el string a cifrar (ej: kernel32.dll): ").strip()
    if not texto:
        texto = "kernel32.dll"
        print(f"  (usando valor por defecto: {texto})")

    print()
    print("  Parametros del algoritmo:")
    print("  - Clave (k): numero que actuara como terminador (1-126)")
    print("  - Multiplicador: debe ser coprimo con 127")
    print("    Ejemplos validos: 3, 5, 7, 9, 11, 13, 17, 23, 25...")
    print()

    try:
        clave = int(input("  Ingresa la clave (ej: 99): ").strip())
        multiplicador = int(input("  Ingresa el multiplicador (ej: 11): ").strip())
    except ValueError:
        print("  Valor invalido. Usando clave=99, multiplicador=11")
        clave, multiplicador = 99, 11

    print()

    try:
        bytes_cifrados = cifrar_string(texto, clave, multiplicador)

        print(f"  String original : '{texto}'")
        print(f"  Clave           : {clave}")
        print(f"  Multiplicador   : {multiplicador} (0x{multiplicador:02x})")
        print()
        print(f"  Bytes cifrados  : {[hex(b) for b in bytes_cifrados]}")

        mostrar_bytes_como_ghidra(bytes_cifrados, "local_XX")

    except ValueError as e:
        print(f"\n  Error: {e}")
        return

    # -----------------------------------------------------------
    # PARTE 2: DESCIFRADO
    # Aplicamos la operacion inversa exactamente como lo hace LockBit
    # -----------------------------------------------------------
    print()
    print("-" * 60)
    print("  PARTE 2: DESCIFRADO")
    print("  Replica el loop do/while de LockBit en Ghidra")
    print("-" * 60)
    print()
    print("  Aplicando la formula:")
    print("  byte_nuevo = ((clave - byte_original) * multiplicador")
    print("                % 0x7f + 0x7f) % 0x7f")
    print()

    resultado = descifrar_bloque(bytes_cifrados, clave, multiplicador)

    print("  Proceso byte por byte:")
    print(f"  {'Pos':>4}  {'Cifrado':>8}  {'Formula':>35}  {'Resultado':>10}  {'ASCII':>5}")
    print(f"  {'-'*4}  {'-'*8}  {'-'*35}  {'-'*10}  {'-'*5}")

    for i, (b_enc, b_dec) in enumerate(zip(bytes_cifrados, resultado)):
        formula = f"(({clave} - {b_enc:3d}) * {multiplicador}) mod 127"
        if b_dec == 0:
            ascii_char = "\\0 (nulo)"
        elif 32 <= b_dec <= 126:
            ascii_char = f"'{chr(b_dec)}'"
        else:
            ascii_char = f"0x{b_dec:02x}"
        print(f"  {i:>4}  {b_enc:>8}  {formula:>35}  {b_dec:>10}  {ascii_char:>5}")

    print()
    resultado_texto = bytes(resultado).rstrip(b'\x00').decode('ascii', errors='replace')
    print(f"  String descifrado: '{resultado_texto}'")
    print()

    # Verificacion
    if resultado_texto == texto:
        print("  Verificacion: CORRECTA - el descifrado reprodujo el string original")
    else:
        print("  Verificacion: DIFERENCIA detectada")
        print(f"  Original  : '{texto}'")
        print(f"  Descifrado: '{resultado_texto}'")

    # -----------------------------------------------------------
    # PARTE 3: EJEMPLO CON LOS VALORES REALES DE LOCKBIT
    # Para que el lector compare con lo que ve en Ghidra
    # -----------------------------------------------------------
    print()
    print("-" * 60)
    print("  PARTE 3: VALORES REALES DE LOCKBIT (bloque 1)")
    print("  Estos son los bytes exactos que aparecen en Ghidra")
    print("-" * 60)
    print()

    lockbit_bytes = [0x14, 9, 0x36, 0x59, 9, 0x2b, 2, 0x6a,
                     0xe, 0x71, 0x2b, 0x2b, 99]
    lockbit_clave = 99
    lockbit_mult  = 0xb

    resultado_lb = descifrar_bloque(lockbit_bytes, lockbit_clave, lockbit_mult)
    texto_lb = bytes(resultado_lb).rstrip(b'\x00').decode('ascii', errors='replace')

    print(f"  Bytes en Ghidra : {[hex(b) for b in lockbit_bytes]}")
    print(f"  Clave           : {lockbit_clave}")
    print(f"  Multiplicador   : 0x{lockbit_mult:02x} ({lockbit_mult})")
    print(f"  String real     : '{texto_lb}'")
    print()
    print("=" * 60)


if __name__ == "__main__":
    main()
