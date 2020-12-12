import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
from torchvision import datasets, transforms
from torch.optim.lr_scheduler import StepLR
import tenseal as ts
import pandas as pd
import prepare_data
from time import time
import numpy as np

# Data
from keras.datasets import mnist
# Plotting
from matplotlib import pyplot


# Plaintext CNN
class CNN():
    def __init__(self):
        self.conv1 = nn.Conv2d(1, 32, 3, 1)
        self.conv2 = nn.Conv2d(32, 64, 3, 1)
        self.dropout1 = nn.Dropout(0.25)
        self.dropout2 = nn.Dropout(0.5)
        self.fc1 = nn.Linear(9216, 128)
        self.fc2 = nn.Linear(128, 10)

    @staticmethod
    def sigmoid(enc_x):
        return enc_x.polyval([0.5, 0.197, 0, -0.004])

    def forward(self, x):
        x = self.conv1(x)
        x = CNN.sigmoid(x)
        x = self.conv2(x)
        x = CNN.sigmoid(x)
        x = F.max_pool2d(x, 2)
        x = self.dropout1(x)
        x = torch.flatten(x, 1)
        x = self.fc1(x)
        x = CNN.sigmoid(x)
        x = self.dropout2(x)
        x = self.fc2(x)
        output = F.log_softmax(x, dim=1)
        return output

    '''
    This is performed as a subroutine of Conv
    stridex: int
    stridey: int
    filterSize: int
    width: int
    length: int
    encImage: [Ciphertext]
    filter: [int]
    zero: Ciphertext
    filteredImages: [[Ciphertext]]
    sequence: int
    '''
    def filterEncryptedImage(self, stridex, stridey, filterSize, width, length, encImage, filter, zero, filteredImages, sequence):
        pad = filterSize / 2
        filteredImage = [] # List to store

        l = pad
        mul_round = 0
        while l < length - pad:
            e = pad
            while e < width - pad:
                v = zero
                for i in range(filterSize):
                    y = l - pad + i
                    if y >= 0 and y < length:
                        for j in range(filterSize):
                            x = e - pad + j
                            if x >= 0 and x < width:
                                v1 = encImage[int(y) * width + int(x)]
                                mul = filter[i * filterSize + j]
                                if mul != 0:
                                    print(mul_round) # debug
                                    mul_round += 1
                                    mul_vector = [mul] * v1.size()
                                    v1 *= mul_vector
                                    v += v1
                filteredImage.append(v)
                e += stridex
            l += stridey
        filteredImages[sequence] = filteredImage
        return filteredImages


    '''
    '''
    def filterEncryptedImageAdd(self, stridex, stridey, filterSize, width, length, encImage, filter, zero, filteredImages, sequence):
        pad = filterSize / 2
        a = 0
        l = pad
        while l < length - pad:
            e = pad
            while e < width - pad:
                v = zero
                for i in range(filterSize):
                    y = l - pad + i
                    if y >= 0 and y < length:
                        for j in range(filterSize):
                            x = e - pad + j
                            if x >= 0 and x < width:
                                v1 = encImage[int(y) * width + int(x)]
                                mul = filter[i * filterSize + j]
                                if mul != 0:
                                    mul_vector = [mul] * v1.size()
                                    v1 *= mul_vector
                                    v += v1
                filteredImages[sequence][a] += v
                a += 1
                e += stridex
            l += stridey

        return filteredImages

    '''
    Conv layer
    stridex: int
    stridey: int
    filterSize: int
    width: int
    length: int
    encImage: [Ciphertext]
    noOfFilters: int
    filters: [[int]]
    zero: Ciphertext
    filteredImages: 
    '''
    def convOperationParallel(self, stridex, stridey, filterSize, width, length, encImage, noOfFilters, filters, zero, filteredImages):
        for i in range(noOfFilters):
            fi = []
            filteredImages.append(fi)
            filteredImages = self.filterEncryptedImage(stridex, stridey, filterSize, width, length, encImage, filters[i], zero, filteredImages, i)

        return filteredImages



    '''
    '''
    def convOperationParallelAdd(self, stridex, stridey, filterSize, width,
		length, encImage, noOfFilters, filters,
		zero, filteredImages):
        for i in range(noOfFilters):
            self.filterEncryptedImageAdd(stridex, stridey, filterSize, width, length, encImage, filters[i], zero, filteredImages, i)

        return filteredImages

    '''
    Pooling
    poolSize: int
    width: int
    length: int
    encImage: [Ciphertext]
    zero: Ciphertext
    pooledImages: [[Ciphertext]]
    sequence: int
    '''
    def poolEncryptedImage(self, poolSize, width, length, encImage, zero, pooledImages, sequence):
        pooledImage = [] # To store ciphertexts
        for l in range(0, length, 2):
            for e in range(0, width, 2):
                v = zero
                for i in range(poolSize):
                    y = l + i
                    if y >= 0 and y < length:
                        for j in range(poolSize):
                            x = e + j
                            if x >= 0 and x < width:
                                v += encImage[(l + i) * width + e + j]
                pooledImage.append(v)
        pooledImages[sequence] = pooledImage
        return pooledImages


    '''
    Activate encrypted image
    '''
    def activateEncryptedImage(self, encImage, images, sequence):
        for j in range(encImage.size()):
            self.sigmoid(encImage[j])
        images[sequence] = encImage
        return images

    '''
    Encrypt model
    '''
    #def encrypt(self, context):

    '''
    Decrypt model
    '''
    #def decrypt(self):



# Load data
(x_train, y_train), (test_X, test_y) = mnist.load_data()
x_train = x_train[:1]
y_train = y_train[:1]
# Encryption parameters
poly_mod_degree = 16384
coeff_mod_bit_sizes = [60, 40, 40, 40, 40, 60, 60, 40, 50]
# create TenSEALContext
ctx_training = ts.context(ts.SCHEME_TYPE.CKKS, poly_mod_degree, -1, coeff_mod_bit_sizes)
ctx_training.global_scale = 2 ** 20
ctx_training.generate_galois_keys()



# Encrypt images
print("Encrypt images")
t_start = time()
# Not fixed: this number comes from sizes of MNIST pictures
width = 28
length = 28
# Encrypt the images in a batching way
encImage = []
for i in range(width * length):
    lp1 = []
    for b in range(len(x_train)):
        lp1.append(x_train[b][i // width][i % width])
    lp1_enc = ts.ckks_vector(ctx_training, lp1)
    encImage.append(lp1_enc)


# Decrypt
decrypted = []
for enc in encImage:
    decrypted.append(enc.decrypt())

print(x_train)
print(decrypted)
print(np.array(decrypted).reshape(28, 28))

"""
# In MNIST set, y labels should be the digit class
enc_y_train = ts.ckks_vector(ctx_training, y_train)
t_end = time()
print(f"Encryption of the training_set took {int(t_end - t_start)} seconds")

# Training
# Fixed
filterSize = 3
poolSize = 2
stridex = 1
stridey = 1
maxFilterSize = 64


zero_plain = [0]
zero = ts.ckks_vector(ctx_training, zero_plain)
CNN = CNN()
print("Generating filters...")
filters = []
for f in range(maxFilterSize):
    filter = []
    for i in range(filterSize * filterSize):
        filter.append(1)
    filters.append(filter)

# Conv_1
noOfFilters = 16
print("Conv starts...")
print("Filters: " + str(noOfFilters) + "...")
convOut1 = [[]]
convOut1 = CNN.convOperationParallel(stridex, stridey, filterSize, width, length, encImage, noOfFilters, filters, zero, convOut1)

# Activation_1
print("Activation starts...")
width = 26
length = 26
actOut1 = [[]]
for i in range(convOut1.size()):
    actImage = []
    actOut1.append(actImage)
    CNN.activateEncryptedImage(convOut1[i], actOut1, i)

# Conv_2
noOfFilters = 16
print("Conv starts...")
print("Filters: " + noOfFilters + "...")

width = 26
length = 26

convOut2 = [[]]
convOut2 = CNN.convOperationParallel(stridex, stridey, filterSize, width, length, actOut1[0], noOfFilters, filters, zero, convOut2)
for i in range(1, actOut1.size()):
    convOut2 = CNN.convOperationParallelAdd(stridex, stridey, filterSize, width, length, actOut1[i], noOfFilters, filters, zero, convOut2)

print("Time for conv = ")
print("Size after conv: " + convOut2[0].size())
print("Depth after conv: " + convOut2.size())

# ----- Activation_2 -----
print("Activation starts...")

width = 24
length = 24

actOut2 = [[]]
for i in range(convOut2.size()):
    actImage = []
    actOut2.append(actImage)
    CNN.activateEncryptedImage(convOut2[i], actOut2, i)

# ----- Conv_3 -----
noOfFilters = 32
width = 24
length = 24

convOut3 = [[]]
convOut3 = CNN.convOperationParallel(stridex, stridey, filterSize, width, length, actOut2[0], noOfFilters, filters, zero, convOut3)
for i in range(1, actOut1.size()):
    convOut3 = CNN.convOperationParallelAdd(stridex, stridey, filterSize, width, length, actOut2[i], noOfFilters, filters, zero, convOut3)


# Conv_4
noOfFilters = 32
width = 22
length = 22

convOut4 = [[]]
convOut4 = CNN.convOperationParallel(stridex, stridey, filterSize, width, length, convOut3[0], noOfFilters, filters, zero, convOut4)
for i in range(1, convOut4.size()):
    convOut4 = CNN.convOperationParallelAdd(stridex, stridey, filterSize, width, length, convOut3[i], noOfFilters, filters, zero, convOut4)

# Activation_3
width = 22
length = 22

actOut3 = [[]]
for i in range(convOut3.size()):
    actImage = []
    actOut3.append(actImage)
    CNN.activateEncryptedImage(convOut4[i], actOut3, i)

# ----- Conv_5 -----
noOfFilters = 10
width = 22
length = 22

convOut5 = [[]]
convOut5 = CNN.convOperationParallel(stridex, stridey, filterSize, width, length, convOut4[0], noOfFilters, filters, zero, convOut5)
for i in range(1, convOut4.size()):
    convOut5 = CNN.convOperationParallelAdd(stridex, stridey, filterSize, width, length, convOut4[i], noOfFilters, filters, zero, convOut5)

"""

# Obtain the final probability vector
#for i in range(convOut5.size()):
    #for j in range(convOut5.size()):


# Testing