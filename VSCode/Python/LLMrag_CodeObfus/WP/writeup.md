# 论文笔记

# SrcMarker

## 实现思路

### Transformer

#### 总述

整体变换逻辑位于`./mutable_tree/tree_manip/visitors`目录下：

| ![image-20250326194626385](./writeup.assets/image-20250326194626385.png) |
| :----------------------------------------------------------: |

##### ==注意==

如果想屏蔽掉一些上述的代码转换风格，只采用你选定的代码转换去添加水印：

> 可以在：`mutable_tree/transformers/utils.py`中将你想屏蔽掉的转换风格注释掉即可：
> 
>| ![image-20250525170753794](./writeup.assets/image-20250525170753794.png) |
> | ------------------------------------------------------------ |
> 
>上面这部分在训练过程中并未使用...
> 
>同时在`train_main.py`中注释掉如下部分即可：
> 
>| ![image-20250525232139140](./writeup.assets/image-20250525232139140.png) |
> | ------------------------------------------------------------ |
> 
>KeyError: ('IfBlockSwapTransformer.normal', 'CompoundIfTransformer.if_compound', 'ConditionTransformer.switch', 'LoopTransformer.for_loop', 'InfiniteLoopTransformer.literal_true', 'UpdateTransformer.prefix_update', 'SameTypeDeclarationTransformer.split', 'VarDeclLocationTransformer.block_start', 'VarInitTransformer.split', 'VarNameStyleTransformer.pascal_case')

- 为保证不影响整个项目的运行逻辑，我们找到代码进行转换的源头：

  也就是`mutable_tree/tree_manip/visitors`和`mutable_tree/transformers`这里

  为最小化修改代价同时保证正常运行，将没有选择的变换置空转，即让其失效：

  在`mutable_tree/transformers`路径下的各个转换模块中，让`mutable_tree_transform`函数直接返回`node`即可：

  ```python
  def mutable_tree_transform(self, node: Node, dst_style: str):
      # return {
      #     self.TRANSFORM_COND_SWITCH: SwitchToIfVisitor(),
      #     self.TRANSFORM_COND_TERNARY: TernaryToIfVisitor(),
      # }[dst_style].visit(node)
      
      return node
  ```

  | ![image-20250526113919545](./writeup.assets/image-20250526113919545.png) |
  | ------------------------------------------------------------ |

- 同时也可以屏蔽掉模型自适应重命名变量的模块

  该模块位于`trainers/ultimate_var_trainer.py`这里，调用了：
  `self.transform_manager.varname_transform_on_instances`模块

  只需要将`runtime_data_manager.py`中的这个模块做如下修改：

  ```python
  def varname_transform_on_instances(
      self, instances: List[DataInstance], word_preds: List[int], mode: str
  ) -> Tuple[List[DataInstance], List[Tuple[str, str]]]:
      assert self.vocab is not None
  
      new_instances = []
      updates = []
      for instance, word_pred in zip(instances, word_preds):
          new_word = self.vocab.get_token_by_id(word_pred)
          new_instance, update = self._jit_varname_substitution(
             instance, new_word, mode=mode
          )
          new_instances.append(new_instance)
          updates.append(update)
  
      # return new_instances, updates
      return instances, [("", "") for _ in instances]
  	# 这里如果返回的是空列表[]的话，会导致后面eval_main.py脚本执行logger.info(f"Variable Updates: {updates[i]}")时报错
  ```
  
  | ![image-20250526130342228](./writeup.assets/image-20250526130342228.png) |
  | ------------------------------------------------------------ |


然后再训练模型并进行模型评估：（训练时的epoch可以适当小些）

```python
# training a 4-bit GRU model on CSN-Java
python train_main.py \
    --lang=java \
    --dataset=csn_java \
    --dataset_dir=./datasets/csn_java \
    --n_bits=4 \
    --epochs=25 \
    --log_prefix=4bit_gru_srcmarker \
    --batch_size 64 \
    --model_arch=gru \
    --shared_encoder \
    --varmask_prob 0.5 \
    --seed 42

# run an evaluation on CSN-Java, using some 4-bit GRU checkpoints
python eval_main.py \
    --checkpoint_path <path_to_model_checkpoint> \
    --lang java \
    --dataset csn_java \
    --dataset_dir ./datasets/csn_java \
    --n_bits 4 \
    --model_arch=gru \
    --shared_encoder \
    --write_output
```



#### 变量处理风格

##### [变量命名风格](ToCamelCaseVisitor(), ToPascalCaseVisitor(), ToSnakeCaseVisitor(), ToUnderscoreCaseVisitor())

- CamelCase：

  驼峰命名法：首个单词首字母小写，后续单词首字母大写，单词之间不使用分隔符。

- PascalCase：

  帕斯卡命名法，大驼峰：每个单词首字母都大写，单词之间不使用分隔符。

- SnakeCase：

  蛇形命名法：所有单词小写，单词之间用 **下划线 `_`** 连接。

- UnderscoreCase：

  下划线命名法，常用于常量：所有字母 **大写**，单词之间用 **下划线 `_`** 连接。

##### [相同变量声明拆分/合并](SplitVarWithSameTypeVisitor(), MergeVarWithSameTypeVisitor())

| 同类型变量拆分                         | 同类型变量合并                                         |
| -------------------------------------- | ------------------------------------------------------ |
| // 原代码（合并声明）<br/>int a, b, c; | // 变换后（拆分声明）<br/>int a;<br/>int b;<br/>int c; |

##### [变量声明初始化拆分/合并](SplitVarInitAndDeclVisitor(), MergeVarInitAndDeclVisitor())

- `TRANSFORM_INIT_SPLIT`（拆分声明和初始化）
- `TRANSFORM_INIT_MERGE`（合并声明和初始化）

##### [变量声明调整](MoveVarDeclToHeadVisitor(), MoveVarDeclToBeforeUsedVisitor())

- `TRANSFORM_VARDECL_BLOCK_START`（移动到代码块开头）
- `TRANSFORM_VARDECL_FIRST_USE`（移动到第一次使用之前）

##### [自增自减变量更新](PrefixUpdateVisitor(), PostfixUpdateVisitor())

`x++`/`++x`
`y--`/`--y`

##### [二元更新运算](BinopUpdateVisitor())

将 `x = x + 1` 或 `x = x - 1` 之类的赋值运算转换为 `x += 1` 或 `x -= 1`。

##### [赋值更新](AssignUpdateVisitor())

将 `x += 1` 形式的操作转换为 `x = x + 1`。



#### 代码转换风格

##### 条件判断

###### [结构转换](SwitchToIfVisitor(), TernaryToIfVisitor())

| 标准的`if-else`结构                                        | `Switch`结构                                                 | 三元组简写结构                                    |
| :--------------------------------------------------------- | :----------------------------------------------------------- | :------------------------------------------------ |
| if .....{<br />// 代码块<br />}else{<br />// 代码块<br />} | switch (expression) {<br/>    case value1:<br/>        // 代码块<br/>        break;<br/>    case value2:<br/>        // 代码块<br/>        break;<br/>    default:<br/>        // 默认代码块（可选）<br/>} | result = true_value if condition else false_value |

###### [嵌套if的拆分和合并](CompoundIfVisitor(), NestedIfVisitor())

| 拆分                                                         | 合并                                                 |
| ------------------------------------------------------------ | ---------------------------------------------------- |
| if x > 0:<br/>    if y > 0:<br/>        print("x 和 y 都大于 0") | if x > 0 and y > 0:<br/>    print("x 和 y 都大于 0") |

###### [if-else转换](NormalBlockSwapper(), NegatedBlockSwapper())

| 保持`if`结构                                                 | 交换`if-else`代码块，并取反条件                              |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| if x > 0:<br/>    print("x 是正数")<br/>else:<br/>    print("x 不是正数") | if x <= 0:<br/>    print("x 不是正数")<br/>else:<br/>    print("x 是正数") |

##### 循环

###### [无限循环条件](LoopLiteralOneVisitor(), LoopLiteralTrueVisitor())

| InfiniteLoopTransformer.literal_true | InfiniteLoopTransformer.literal_1 |
| ------------------------------------ | --------------------------------- |
| while(ture)                          | while(1)                          |

###### [循环方式](WhileToForVisitor(), ForToWhileVisitor())

| for循环 | while循环 |
| ------- | --------- |
|         |           |

是不是do-while也可以算一种风格呢



#### 与代码混淆方式比较

1. Change linear code execution flow to nonlinear version

   线性代码序列转换为非线性（使用循环以及条件判断等方式）

   水印中与之相对应的操作低一个档次

   水印中只是改变条件循环结构体的风格，而这种混淆方式可以无中生有，甚至干扰语义理解

   理论上这个项目的水印无法抵抗这种混淆攻击

2. Rename variable/method names to random string values

   随机化变量/方法名

   此混淆方式可以破坏水印中对变量的命名方法

   由于几乎每个函数(方法)中都会有变量名，这种混淆方式可以影响绝大部分的代码

3. Shuffle order of methods in the output source

   改变方法的声明顺序

   水印中**没有**相对应的操作

4. Encrypt integer values using floating point math functions

   常量加密

   水印中**没有**相对应的操作

5. Encrypt strings using randomly generated polymorphic encryption algorithms

   使用随机生成的多态加密算法加密字符串

   水印中**没有**相对应的操作

6. Extract every integer/double value from the methods and store them in an array

   从方法中提取每个整数/双精度值并将其存储在数组中

   水印中**没有**相应操作

##### 总结

以这个项目给出的代码转换这一层面的水印(不咋影响源代码执行效率，且有一定的可读性)，理论上无法承受这种能把代码改的面目全非的混淆攻击



### 关于损失函数

论文中包含了三个损失函数：

| <img src="./writeup.assets/image-20250326160516145.png" alt="image-20250326160516145" style="zoom: 50%;" /> | 1. $L_{approx}$：<br />`warper_dist_loss`：**近似特征**和**真实特征**之间的损失<br /><br />2. $L_{dec}^{(approx)}$<br />`decode_loss`：水印近似特征解码损失<br />3. $L_{dec}^{(actual)}$<br />`t_loss`：真实变换代码的解码损失 |
| :----------------------------------------------------------: | :----------------------------------------------------------- |

```python
loss = decode_loss + t_loss + 0.25 * warper_dist_loss
loss.backward()
```





### 操作日志

python 1_obfus.py --sample --sample_size 10



python 2_eval_obfus.py     --checkpoint_path ./ckpts/4bit_gru_srcmarker_42_csn_java/models_best.pt     --lang java     --dataset csn_java     --dataset_dir ./datasets/csn_java/     --n_bits 4     --model_arch=gru     --shared_encoder   --output_filename java_4bit_obfus_ai_GPT_paid_rules1.jsonl

#### 3.21实验结果

- 使用代码混淆工具按照`Rename method names to random string values`规则混淆后水印提取效果：

  | <img src="./writeup.assets/image-20250407215038085.png" alt="image-20250407215038085" style="zoom:50%;" /> |
  | :----------------------------------------------------------- |

#### 4.07实验结果

选取整个加水印代码群体中代码长度最长的50个进行实验：

- AI(gpt4)按照`Change linear code execution flow to nonlinear version`规则混淆后水印提取效果：

  | <img src="./writeup.assets/image-20250407212327740.png" alt="image-20250407212327740" style="zoom:50%;" /> |
  | ------------------------------------------------------------ |

  很奇怪，这个攻击成功率很低

  难道说是因为水印特征主要都在变量命名风格中？

- AI(kimi)按照`Rename variable/method names to random string values`规则混淆后水印提取效果：

  | <img src="./writeup.assets/image-20250407214638111.png" alt="image-20250407214638111" style="zoom:50%;" /> |
  | ------------------------------------------------------------ |

- AI(gpt4)按照`Rename variable/method names to random string values`规则混淆后水印提取效果：

  | <img src="./writeup.assets/image-20250407221912929.png" alt="image-20250407221912929" style="zoom:50%;" /> |
  | ------------------------------------------------------------ |

  这个现象在预期之内，说明该项目的代码水印的特征主要集中在变量名中
  
- 

  | <img src="./writeup.assets/image-20250408100250039.png" alt="image-20250408100250039" style="zoom:50%;" /> |
  | ------------------------------------------------------------ |


#### 6.01: RAG+Prompt测试结果

输入自己认为很概括的prompt得到的识别模式以及混淆的效果并不是特别好：

```prompt
public static void main(String[] args) {
        double price = 200.0;
        int level = 2;

        double result = calculateDiscountedPrice(price, level);
        System.out.println("Final Price: " + result);
    }
请你对上述代码执行tag1_2的代码混淆操作：即随机化变量的声明位置(将其随机放置于第一次使用之前，同时保证在其原生命周期及作用域内)
```

~~~answer
<think>
好的，我现在需要帮助用户对一段Java代码应用名为“局部变量实体声明位置随机化”的代码混淆技术。首先，我得理解用户提供的所有上下文和要求。

用户的原始代码是在一个名为Example的类中定义了一个静态方法internalParseDate，该方法处理日期解析。用户还提供了三个其他例子，每个例子都是对不同的局部变量进行位置的随机化。例如，在第一个例子中，变量result被从赋值语句后面移到了if条件前面。

现在，用户给了一个需要执行混淆操作的代码段，其中有一个静态方法calculateDiscountedPrice调用，并计算价格折扣后的结果。我的任务是识别这个方法中的局部变量，然后将它们的位置进行随机化处理，确保声明位置在第一次使用之前，并且保持其作用域和生命周期不变。

首先，我需要查看calculateDiscountedPrice方法内部的代码结构。假设该方法内部有如下的局部变量：

- double result;
- int level;

因为level已经被赋值为2了，所以可能是一个参数，而不是局部变量。那result是局部变量吗？或者它是否被传递进去？根据上下文，似乎result是在外部赋值给参数，然后在方法内部计算，所以可能result不是局部变量。

但假设在这个代码中，result确实是作为局部变量使用的，那么我需要将它的声明位置从赋值的地方移到其他地方。比如，把赋值语句移动到if条件之前或之后，但确保它在第一次使用前被声明。

另外，在混淆过程中，还要注意变量的类型和作用域是否正确。例如，如果内部有一个方法调用calculateDiscountedPrice，并且该方法中有一些局部变量，我需要将它们的位置进行随机化，同时保持逻辑不变。

现在，考虑到代码结构，我可能需要把赋值result = calculateDiscountedPrice(...)移到if条件的前面或后面，或者调整到它所在的其他位置。例如，在例子1和2中，result被移动到了if条件前，并且在结果为空时返回null。

但是在这个新问题中，代码段已经是一个静态方法调用，可能内部还有一些局部变量，比如result和level（如果level不是参数而是局部变量的话）。但根据用户提供的代码，level已经被赋值为2了，所以它可能不是一个局部变量。

综上所述，我需要将结果计算后的变量声明位置进行调整。例如，在方法的开头部分，先声明result，并将其赋值到调用的结果中，然后在if条件或else块中处理逻辑。或者，将赋值语句移动到其他合适的位置，同时保持代码的功能不变。

最后，确保所有操作都符合用户提供的混淆技术要求：随机化变量的声明位置，但保证其生命周期和作用域不受影响。
</think>

根据您提供的代码，以下是应用“局部变量实体声明位置随机化”的结果：

```java
public static void main(String[] args) {
        double price = 200.0;
        int level = 2;

        double result; // 随机化为result而不是在赋值时声明
        result = calculateDiscountedPrice(price, level); // 将赋值移到前面

        if (result == null || result <= 0) { // 保持一致
            System.out.println("Final Price: " + result);
        } else {
            System.out.println("Final Price: " + result); // 保持一致
        }
    }
```

注意：该代码示例中保留了`result`的逻辑和功能，仅调整了变量的声明位置。
~~~

有时还会出现在执行`tag1_2`的混淆方式时引用`tag1_1`的混淆向量的情况

为了构造精确的`prompt`模版，直接复用向量数据库的中的描述文本：

```prompt
[obfus_level] tag1_2
[obfus_desc] Named local variable entity declaration position randomization.
[content] Randomize the declared positions of local variable entities that can be named within a function, while limiting their positions to before the variable's first use and within its scope.
[original_code]
//write original code

Please provide the obfuscated code according to the obfuscation method described above.
```



# DeCoMa

这篇论文《DeCoMa: Detecting and Purifying Code Dataset Watermarks through Dual Channel Code Abstraction》主要提出了一种名为 **DeCoMa** 的新方法，用于**检测和清除代码数据集中的水印**。其核心贡献和工作内容可以总结如下：

------

## 🌟 论文概述

1. **研究背景与动机**：

   - 神经代码模型（NCM）在诸如代码补全、搜索、总结等任务中广泛应用，依赖于大规模、高质量的代码数据集。
   - 由于这些数据集具有高商业价值，因此研究者发展了水印技术（如 CoProtector 和 CodeMark）来防止数据被盗用。
   - 然而，目前缺乏针对代码水印的专门攻击和清除方法，现有检测技术（如 AC、SS、CodeDetector）对代码水印几乎无效。

2. **方法创新：DeCoMa 系统**：

   - **Dual-channel Abstraction**：代码同时具有“自然通道”（如变量名、注释）和“形式通道”（程序结构和执行逻辑），DeCoMa 利用这一点将代码抽象为标准模板（ACT）。
   - **模板构建**：将代码映射为三类模板：
     - **抽象标识符模板（AI）**
     - **抽象表达式模板（AE）**
     - **抽象注释模板（AC）**
   - **水印检测方法**：通过分析模板之间的**异常共现频率对（trigger-target pairs）**，用 z-score 异常检测方法找出水印模式。
   - **水印清除策略**：在检测出水印后，直接从数据集中删除所有包含这些 trigger-target 模板对的样本，达到净化目的。

3. **实验与评估**：

   - 实验覆盖 **14 种代码水印情景**，包括 CoProtector、CodeMark、BadCode、AFRAIDOOR 四种技术，三类任务（代码补全、搜索、摘要）。
   - **检测效果显著优于现有方法**，所有情景下召回率均达 **100%**，远超 AC（平均36%）、SS（平均6%）等。
   - **效率大幅提升**：相比基线方法（20~60小时），DeCoMa 在450K规模数据集上**检测时间仅需17分钟**（加速达130倍）。
   - **净化后模型性能无明显损失**，并成功绕过水印验证。

4. **研究意义与贡献总结**：

   - 首次将“代码的双通道结构”引入到水印检测中，提出具鲁棒性和通用性的水印攻击方法。
   - 提供一个无需模型训练、依赖静态代码分析的高效攻击框架。
   - 公开 DeCoMa 代码，有助于未来代码水印防御方法的开发与评估。

   对数据集级别的水印检测更符合现实，**攻击者目标并非某一条代码样本，而是整个数据集**。在现实中，攻击者往往盗用一批数据（如开源库爬取、公开数据集收集）用于训练神经代码模型（如 CodeT5、Codex 等）。

   如果只对单个样本检测，即便检测出水印，也无法构成**有效清洗策略**，更无法判断“整体数据集是否受污染”，攻击者也无从决策“是否可以安全使用”。

## 实现细节

### 双通道抽象映射

#### 解析为抽象语法树

有一个**代码数据集** $D$，里面的每一条数据是一个**(c, s)对**，

- 其中 $c$ 是一段**代码**（code），

- $s$ 是对应的**注释**（comment）。

- > **那什么是 code-comment pair？**
  >
  > 就是**一段代码和它的解释/注释组成的一对**。比如：
  >
  > ```
  > python复制编辑# 计算两个数的和
  > def add(a, b):
  >     return a + b
  > ```
  >
  > - 这里的 code $c$ 是 `def add(a, b): return a + b` 这段代码，
  > - comment $s$ 是 `计算两个数的和` 这句话。
  >
  > 所以 `(c, s)` 是这一段代码和它对应自然语言描述的一对。

使用**Tree-sitter**这个工具，把每段代码 $c$ **解析成一棵抽象语法树**（AST，abstract syntax tree），记为 $r$。

解析示例：

上述函数解析后如下所示：

```sql
function_definition
├── function_name: "add"
├── parameters
│   ├── parameter: "a"
│   └── parameter: "b"
└── body
    └── return_statement
        └── binary_expression
            ├── left: "a"
            ├── operator: "+"
            └── right: "b"
```

#### 标准化模版

DeCoMa 会根据预定义的**抽象规则**，将代码 $c$ 和注释 $s$ 都转换成**标准化模板**。

这意味着他们不是直接使用原始的代码/注释，而是**将它们转换成统一、抽象化的格式**，比如用 `__identifier__` 来代替具体变量名。

##### 提取标识符

为了抽象出代码中的**标识符**（identifier，比如变量名、函数名），DeCoMa 遍历语法树 $r$ 中的所有节点 $n$，提取那些节点类型为 `identifier` 的文本内容。

也就是说，它在 AST 中找到所有变量名/函数名等“命名元素”。

##### 语义切分与抽象化

接着，DeCoMa 会将每个标识符根据 **camelCase（驼峰命名法）**做语义切分，然后将以下类型的节点统一替换为抽象标记：

- identifier → `__identifier__`
- number → `__num__`
- string → `__str__`

例如：

```python
totalAmount = 100
```

将被处理成：

```python
__identifier__ = __num__
```

并且 `"totalAmount"` 会被切分为 `["total", "Amount"]`。

##### 处理表达式子节点

DeCoMa 再次遍历处理后的 AST。如果某个节点 $n$ 包含一个子节点 $n_c$，其类型是表达式（`expression`），那么就把这个表达式部分也统一抽象成 `__subexpression__`，即对一些复杂的表达式进行更粗粒度的抽象，减少多样性。

> 示例：
>
> 原始代码：
>
> ```python
> total = a + b * c
> ```
>
> 对应的 AST 节点（简化后）：
>
> ```sql
> assignment_statement
> ├── left: identifier ("total")
> └── right: binary_expression
>      ├── left: identifier ("a")
>      ├── operator: "+"
>      └── right: binary_expression
>           ├── left: identifier ("b")
>           ├── operator: "*"
>           └── right: identifier ("c")
> ```
>
> 如果我们只做了前几步，会抽象成：
>
> ```python
> __identifier__ = __identifier__ + __identifier__ * __identifier__
> ```
>
> 虽然已经比原始代码通用，但还是不够紧凑。
>
> **于是：**
>
> - 检查 `right`（右值）这个节点，它是一个复杂的表达式；
> - 将整个表达式抽象为一个统一模板：
>
> ```python
> __identifier__ = __subexpression__
> ```

##### 处理注释

对于每一条注释 $s$，DeCoMa 会按照空格将其切分成一个个单词（token）。

比如：

```python
"calculate total amount"
→ ["calculate", "total", "amount"]
```

##### 最终输出

最后，DeCoMa 会输出以下三种抽象模板，作为后续代码水印检测的基础：

- **AI（Abstracted Identifiers）**：标识符抽象模板；
- **AE（Abstracted Expressions）**：表达式抽象模板；
- **AC（Abstracted Comments）**：注释抽象模板。
