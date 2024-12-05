import pandas as pd

df = pd.read_csv('page_fault_dataset.csv')
print(len(df))

print(df.iloc[:, 0].nunique())

a = df.iloc[:,0].to_numpy()
print('Shape: ', a.shape)
b = set()
for i in range(a.shape[0]):
    b.add(a[i])

print(len(b))

last_col = df['page_fault'].to_numpy()
count_0 = (last_col == 0).sum()
count_1 = (last_col == 1).sum()

print(count_0)
print(count_1)
