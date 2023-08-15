<?php
	if(isset($_POST["email"]) && isset($_POST["password"])){//當偵測到我有資料進來
		$errors = array(); //設定若發生error所要輸出的字串
		
		$email = $_POST["email"]; //抓信箱輸入
		$password = $_POST["password"]; //抓密碼輸入

		$sql = "SELECT username, email, password FROM sc_users WHERE email = ? LIMIT 1";
		
		//連結資料庫資訊，但目前來講是存在本地電腦
		require __DIR__ . '/database.php'; 
		
		//這邊因為有設定信箱不能一樣，所以找的資料限制一筆
		if ($stmt = $mysqli_conection->prepare($sql)) {
			
			//設定信箱以字串來看，這裡是為了預防sql injection的問題
			$stmt->bind_param('s', $email);
				
			//執行
			if($stmt->execute()){
				
				//儲存結果 這個store_result 跟下面的 fetch 和bind 比較有關聯
				$stmt->store_result();

				if($stmt->num_rows > 0){
					/* bind result variables */
					$stmt->bind_result($username_tmp, $email_tmp, $password_hash);

					/* fetch value */
					$stmt->fetch();
					
					if(password_verify ($password, $password_hash)){
						//這個在unity遊戲製作判斷是否成功登入是抓前面的"Success"來判斷的
						echo "Success" . "|" . $username_tmp . "|" .  $email_tmp;
						
						return;
					}else{
						$errors[] = "密碼或帳號出錯";
					}
				}else{
					$errors[] = "密碼或帳號出錯";
				}
				
				/* close statement */
				$stmt->close();
				
			}else{
				$errors[] = "Something went wrong, please try again.";
			}
		}else{
			$errors[] = "Something went wrong, please try again.";
		}
		
		if(count($errors) > 0){
			echo $errors[0];
		}
	}else{
		echo "Missing data";
	}
?>