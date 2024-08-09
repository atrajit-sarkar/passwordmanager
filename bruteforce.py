import subprocess
import time
start_time=time.time()

passwordsList=[]
with open("passwordlist.txt","r") as f:
    passwords=f.readlines()
for i in passwords:
    i=i.rstrip()
    passwordsList.append(i)

command = "python .\\Decode.py"

try:
    for i in passwordsList:
        input_data = f"passwords.txt\n{i}"
        result = subprocess.run(command, input=input_data, capture_output=True, text=True)
        
        # Strip leading/trailing whitespace and newlines
        output = result.stdout.strip().split(":")[2]
        
        # Print the processed output
        print(f"Processed output: {output}")
        
        # Check if the expected phrase is in the output
        if "File decrypted and saved as passwords.txt" in output:
            print("Hacked Successfully")
            break

except Exception as e:
    print(e)
end_time=time.time()

print(f"Total runtime: {end_time-start_time}")